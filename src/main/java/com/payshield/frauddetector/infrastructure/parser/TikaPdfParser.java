package com.payshield.frauddetector.infrastructure.parser;

import com.payshield.frauddetector.application.InvoiceDetectionService;
import org.apache.tika.metadata.Metadata;
import org.apache.tika.parser.AutoDetectParser;
import org.apache.tika.sax.BodyContentHandler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.io.InputStream;
import java.math.BigDecimal;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Component
public class TikaPdfParser implements InvoiceDetectionService.PdfParser {

    private static final Logger log = LoggerFactory.getLogger(TikaPdfParser.class);

    // Enhanced regex patterns for better extraction
    private static final Pattern VENDOR_PATTERNS[] = {
            Pattern.compile("(?i)(?:vendor|company|supplier)[:\\s]+([A-Za-z0-9&.,\\-\\s]{2,50})"),
            Pattern.compile("(?i)(?:bill\\s+to|invoice\\s+from)[:\\s]+([A-Za-z0-9&.,\\-\\s]{2,50})"),
            Pattern.compile("(?i)^([A-Za-z0-9&.,\\-\\s]{2,50})(?:\\s+(?:ltd|inc|corp|llc|gmbh|limited))", Pattern.MULTILINE),
            Pattern.compile("(?i)from[:\\s]+([A-Za-z0-9&.,\\-\\s]{2,50})")
    };

    private static final Pattern CURRENCY_PATTERNS[] = {
            Pattern.compile("(?i)currency[:\\s]+([A-Z]{3})"),
            Pattern.compile("\\b([A-Z]{3})\\s+[0-9,.]"),  // Currency before amount
            Pattern.compile("([A-Z]{3})\\s*\\$"),          // Currency with $ symbol
            Pattern.compile("\\$\\s*([A-Z]{3})")           // $ with currency
    };

    private static final Pattern IBAN_PATTERNS[] = {
            Pattern.compile("(?i)(?:iban|account)[:\\s]*([A-Z]{2}[0-9]{2}[A-Z0-9\\s]{13,32})"),
            Pattern.compile("\\b([A-Z]{2}[0-9]{2}[A-Z0-9\\s]{13,32})\\b"),  // Standalone IBAN
            Pattern.compile("(?i)international\\s+bank[:\\s]*([A-Z]{2}[0-9]{2}[A-Z0-9\\s]{13,32})")
    };

    private static final Pattern SWIFT_PATTERNS[] = {
            Pattern.compile("(?i)(?:swift|bic)[:\\s]*([A-Z]{6}[A-Z0-9]{2}(?:[A-Z0-9]{3})?)"),
            Pattern.compile("\\b([A-Z]{6}[A-Z0-9]{2}(?:[A-Z0-9]{3})?)\\b")  // Standalone SWIFT
    };

    private static final Pattern AMOUNT_PATTERNS[] = {
            Pattern.compile("(?i)(?:total|amount|sum)[:\\s]*([0-9]{1,3}(?:[,\\s][0-9]{3})*(?:\\.[0-9]{2})?)"),
            Pattern.compile("(?i)(?:grand\\s+total|final\\s+amount)[:\\s]*([0-9]{1,3}(?:[,\\s][0-9]{3})*(?:\\.[0-9]{2})?)"),
            Pattern.compile("\\$\\s*([0-9]{1,3}(?:[,\\s][0-9]{3})*(?:\\.[0-9]{2})?)"),  // Dollar amounts
            Pattern.compile("([0-9]{1,3}(?:[,\\s][0-9]{3})*(?:\\.[0-9]{2})?)\\s*(?:USD|EUR|GBP)")  // Amount with currency
    };

    private static final Pattern BANK_LAST4_PATTERNS[] = {
            Pattern.compile("(?i)account(?:\\s*number)?[:\\s\\-]*\\*{0,12}([0-9]{4})\\b"),
            Pattern.compile("(?i)ending\\s+in[:\\s]*([0-9]{4})\\b"),
            Pattern.compile("(?i)\\*{4,}([0-9]{4})\\b"),  // Masked account ending in 4 digits
            Pattern.compile("(?i)account[:\\s]*[A-Z0-9]*([0-9]{4})\\b")  // Account with last 4
    };

    @Override
    public InvoiceDetectionService.Parsed parse(Path storedPath) {
        log.info("Starting ENHANCED PDF parsing for file: {}", storedPath);

        try (InputStream inputStream = Files.newInputStream(storedPath)) {
            // Use Apache Tika to extract text
            BodyContentHandler handler = new BodyContentHandler(-1);
            Metadata metadata = new Metadata();
            AutoDetectParser parser = new AutoDetectParser();
            parser.parse(inputStream, handler, metadata);

            String text = handler.toString();
            log.info("Extracted text from PDF ({} chars) - First 300 chars: {}",
                    text.length(),
                    text.length() > 300 ? text.substring(0, 300) + "..." : text);

            InvoiceDetectionService.Parsed p = new InvoiceDetectionService.Parsed();

            // ENHANCED: Try multiple patterns for each field
            p.vendorName = extractWithMultiplePatterns(text, VENDOR_PATTERNS, "vendor");
            p.currency = extractWithMultiplePatterns(text, CURRENCY_PATTERNS, "currency");
            p.bankIban = extractAndCleanIban(text);
            p.bankSwift = extractWithMultiplePatterns(text, SWIFT_PATTERNS, "SWIFT");
            p.bankLast4 = extractBankLast4(text, p.bankIban);
            p.amount = extractAmount(text);

            // ENHANCED: Post-processing and validation
            p = validateAndCleanExtractedData(p);

            log.info("ENHANCED PDF parsing completed - vendor: '{}', amount: {}, currency: '{}', " +
                            "IBAN: '{}', SWIFT: '{}', bankLast4: '{}'",
                    p.vendorName, p.amount, p.currency,
                    p.bankIban != null ? p.bankIban.substring(0, 4) + "****" : null,
                    p.bankSwift, p.bankLast4);

            return p;

        } catch (Exception e) {
            log.error("Failed to parse PDF file: {}", storedPath, e);
            throw new RuntimeException("Failed to parse PDF file: " + storedPath, e);
        }
    }

    /**
     * Try multiple regex patterns and return the first match
     */
    private String extractWithMultiplePatterns(String text, Pattern[] patterns, String fieldName) {
        for (int i = 0; i < patterns.length; i++) {
            Pattern pattern = patterns[i];
            try {
                Matcher m = pattern.matcher(text);
                if (m.find()) {
                    String result = m.group(1).trim();
                    log.debug("Field '{}' matched with pattern #{}: '{}'", fieldName, i + 1, result);
                    return result;
                }
            } catch (Exception e) {
                log.warn("Error matching pattern #{} for {}: {}", i + 1, fieldName, e.getMessage());
            }
        }
        log.debug("No patterns matched for field: {}", fieldName);
        return null;
    }

    /**
     * Extract and clean IBAN with enhanced validation
     */
    private String extractAndCleanIban(String text) {
        String iban = extractWithMultiplePatterns(text, IBAN_PATTERNS, "IBAN");

        if (iban != null) {
            // Clean and validate IBAN format
            String cleanIban = iban.replaceAll("[\\s-]", "").toUpperCase();

            // Basic IBAN format validation (country code + 2 digits + alphanumeric)
            if (cleanIban.matches("[A-Z]{2}[0-9]{2}[A-Z0-9]+") && cleanIban.length() >= 15 && cleanIban.length() <= 34) {
                log.debug("Extracted and cleaned IBAN: {} -> {}", iban, cleanIban.substring(0, 4) + "****");
                return cleanIban;
            } else {
                log.warn("Invalid IBAN format after cleaning: '{}' -> '{}'", iban, cleanIban);
                return null;
            }
        }

        return null;
    }

    /**
     * Extract bank account last 4 digits with fallback methods
     */
    private String extractBankLast4(String text, String iban) {
        // Try explicit patterns first
        String last4 = extractWithMultiplePatterns(text, BANK_LAST4_PATTERNS, "bank last4");

        if (last4 != null && last4.length() == 4) {
            return last4;
        }

        // Fallback: extract from IBAN if available
        if (iban != null && iban.length() >= 4) {
            String ibanLast4 = iban.substring(iban.length() - 4);
            log.debug("Extracted bankLast4 from IBAN: {}", ibanLast4);
            return ibanLast4;
        }

        // Last resort: look for any 4-digit sequence near "account"
        Pattern fallbackPattern = Pattern.compile("(?i)account.*?([0-9]{4})");
        Matcher m = fallbackPattern.matcher(text);
        if (m.find()) {
            String fallbackLast4 = m.group(1);
            log.debug("Fallback extraction found bankLast4: {}", fallbackLast4);
            return fallbackLast4;
        }

        log.debug("Could not extract bankLast4 from text or IBAN");
        return null;
    }

    /**
     * Enhanced amount extraction with multiple currency support
     */
    private BigDecimal extractAmount(String text) {
        String amountStr = extractWithMultiplePatterns(text, AMOUNT_PATTERNS, "amount");

        if (amountStr != null) {
            try {
                // Clean the amount string (remove commas, spaces)
                String cleanAmount = amountStr.replaceAll("[,\\s]", "");
                BigDecimal amount = new BigDecimal(cleanAmount);
                log.debug("Successfully parsed amount: '{}' -> {}", amountStr, amount);
                return amount;
            } catch (NumberFormatException e) {
                log.warn("Failed to parse amount '{}': {}", amountStr, e.getMessage());
            }
        }

        // Fallback: Look for any currency symbol followed by amount
        Pattern fallbackAmountPattern = Pattern.compile("[\\$€£]\\s*([0-9]{1,3}(?:[,\\s][0-9]{3})*(?:\\.[0-9]{2})?)");
        Matcher m = fallbackAmountPattern.matcher(text);
        if (m.find()) {
            try {
                String fallbackAmount = m.group(1).replaceAll("[,\\s]", "");
                BigDecimal amount = new BigDecimal(fallbackAmount);
                log.debug("Fallback amount extraction successful: {}", amount);
                return amount;
            } catch (Exception e) {
                log.warn("Fallback amount extraction failed: {}", e.getMessage());
            }
        }

        return null;
    }

    /**
     * Validate and clean extracted data
     */
    private InvoiceDetectionService.Parsed validateAndCleanExtractedData(InvoiceDetectionService.Parsed parsed) {
        // Clean vendor name
        if (parsed.vendorName != null) {
            parsed.vendorName = cleanVendorName(parsed.vendorName);
        }

        // Validate currency
        if (parsed.currency != null && !isValidCurrency(parsed.currency)) {
            log.warn("Invalid currency detected: '{}', setting to null", parsed.currency);
            parsed.currency = null;
        }

        // Validate SWIFT code format
        if (parsed.bankSwift != null && !isValidSwiftFormat(parsed.bankSwift)) {
            log.warn("Invalid SWIFT code format: '{}', setting to null", parsed.bankSwift);
            parsed.bankSwift = null;
        }

        return parsed;
    }

    /**
     * Clean vendor name by removing common PDF extraction artifacts
     */
    private String cleanVendorName(String vendorName) {
        if (vendorName == null) return null;

        // Remove common PDF artifacts and clean up
        String cleaned = vendorName
                .replaceAll("(?i)\\b(?:ltd|inc|corp|llc|limited|corporation)\\b\\.?", "") // Remove legal suffixes temporarily
                .replaceAll("[\\r\\n\\t]+", " ")  // Replace line breaks with spaces
                .replaceAll("\\s{2,}", " ")       // Collapse multiple spaces
                .trim();

        // If the name is too short after cleaning, return original
        if (cleaned.length() < 3) {
            return vendorName.trim();
        }

        return cleaned;
    }

    /**
     * Validate currency code format
     */
    private boolean isValidCurrency(String currency) {
        if (currency == null || currency.length() != 3) return false;

        // Common valid currencies
        Set<String> validCurrencies = Set.of(
                "USD", "EUR", "GBP", "JPY", "AUD", "CAD", "CHF", "CNY", "SEK", "NZD",
                "MXN", "SGD", "HKD", "NOK", "INR", "KRW", "TRY", "RUB", "BRL", "ZAR"
        );

        return validCurrencies.contains(currency.toUpperCase());
    }

    /**
     * Validate SWIFT code format
     */
    private boolean isValidSwiftFormat(String swift) {
        if (swift == null) return false;

        // SWIFT code format: 6 letters (bank code) + 2 letters (country) + 2 alphanumeric (location) + optional 3 alphanumeric (branch)
        return swift.matches("[A-Z]{6}[A-Z0-9]{2}([A-Z0-9]{3})?");
    }

    /**
     * Legacy method - delegates to enhanced extraction
     */
    private static String match(String text, String regex) {
        try {
            Pattern pattern = Pattern.compile(regex);
            Matcher m = pattern.matcher(text);
            if (m.find()) {
                String result = m.group(1).trim();
                log.debug("Legacy regex '{}' matched: '{}'", regex, result);
                return result;
            }
        } catch (Exception e) {
            log.warn("Error matching legacy regex '{}': {}", regex, e.getMessage());
        }
        return null;
    }
}