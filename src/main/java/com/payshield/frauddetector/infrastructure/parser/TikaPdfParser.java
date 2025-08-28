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
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Component
public class TikaPdfParser implements InvoiceDetectionService.PdfParser {

    private static final Logger log = LoggerFactory.getLogger(TikaPdfParser.class);

    @Override
    public InvoiceDetectionService.Parsed parse(Path storedPath) {
        log.info("Starting PDF parsing for file: {}", storedPath);

        try (InputStream inputStream = Files.newInputStream(storedPath)) {
            // Use Apache Tika to extract text from binary PDF file
            BodyContentHandler handler = new BodyContentHandler(-1); // -1 = unlimited
            Metadata metadata = new Metadata();
            AutoDetectParser parser = new AutoDetectParser();
            parser.parse(inputStream, handler, metadata);

            String text = handler.toString();
            log.info("Extracted text from PDF (first 200 chars): {}",
                    text.length() > 200 ? text.substring(0, 200) + "..." : text);

            InvoiceDetectionService.Parsed p = new InvoiceDetectionService.Parsed();

            // Extract vendor name
            p.vendorName = match(text, "(?i)Vendor[:\\s]+([A-Za-z0-9&.,\\-\\s]{2,})");
            log.info("Extracted vendor name: {}", p.vendorName);

            // Extract currency
            p.currency = match(text, "(?i)Currency[:\\s]+([A-Z]{3})");
            log.info("Extracted currency: {}", p.currency);

            // Extract bank IBAN
            p.bankIban = match(text, "(?i)([A-Z]{2}\\d{2}[A-Z0-9]{13,30})");
            log.info("Extracted IBAN: {}", p.bankIban);

            // Extract SWIFT code
            p.bankSwift = match(text, "(?i)\\b([A-Z]{6}[A-Z0-9]{2}([A-Z0-9]{3})?)\\b");
            log.info("Extracted SWIFT: {}", p.bankSwift);

            // Extract bank account last 4 digits
            String last4 = match(text, "(?i)account(?:\\s*number)?[:\\s\\-]*\\*{0,12}([0-9]{4})\\b");
            if (last4 == null && p.bankIban != null && p.bankIban.length() >= 4) {
                last4 = p.bankIban.substring(p.bankIban.length() - 4);
                log.info("Extracted bankLast4 from IBAN: {}", last4);
            }
            p.bankLast4 = last4;
            log.info("Final bankLast4: {}", p.bankLast4);

            // Extract amount
            String amt = match(text, "(?i)(?:Total|Amount)[:\\s]*([0-9]{1,3}(?:[,\\s][0-9]{3})*(?:\\.[0-9]{2})?)");
            if (amt != null) {
                try {
                    p.amount = new BigDecimal(amt.replaceAll("[,\\s]", ""));
                    log.info("Extracted amount: {}", p.amount);
                } catch (Exception e) {
                    log.warn("Failed to parse amount '{}': {}", amt, e.getMessage());
                }
            }

            log.info("PDF parsing completed - vendor: {}, amount: {}, currency: {}, bankLast4: {}",
                    p.vendorName, p.amount, p.currency, p.bankLast4);

            return p;

        } catch (Exception e) {
            log.error("Failed to parse stored PDF file: {}", storedPath, e);
            throw new RuntimeException("Failed to parse stored PDF file: " + storedPath, e);
        }
    }

    private static String match(String t, String re) {
        try {
            Pattern pattern = Pattern.compile(re);
            Matcher m = pattern.matcher(t);
            if (m.find()) {
                String result = m.group(1).trim();
                log.debug("Regex '{}' matched: '{}'", re, result);
                return result;
            } else {
                log.debug("Regex '{}' did not match in text", re);
                return null;
            }
        } catch (Exception e) {
            log.warn("Error matching regex '{}': {}", re, e.getMessage());
            return null;
        }
    }
}