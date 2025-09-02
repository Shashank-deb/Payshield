package com.payshield.frauddetector.domain;

import com.payshield.frauddetector.domain.ports.VendorHistoryRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.math.BigDecimal;
import java.time.DayOfWeek;
import java.time.LocalDateTime;
import java.time.OffsetDateTime;
import java.util.*;

public class DetectionEngine {

    private static final Logger log = LoggerFactory.getLogger(DetectionEngine.class);

    public enum Rule {
        // Existing rules
        NEW_ACCOUNT,
        CHANGED_ACCOUNT,
        INVALID_FORMAT,
        SENDER_MISMATCH,

        // NEW ENHANCED RULES
        IBAN_CHECKSUM_INVALID,     // Mathematical IBAN validation
        VELOCITY_ANOMALY,          // Too many invoices in short period
        AMOUNT_OUTLIER,            // Unusual amount for vendor pattern
        WEEKEND_SUBMISSION,        // Suspicious timing (weekends/holidays)
        DUPLICATE_BANK_ACCOUNT,    // Same bank account used by multiple vendors
        COUNTRY_MISMATCH,          // IBAN country doesn't match vendor
        AMOUNT_THRESHOLD_EXCEEDED, // Above configurable risk threshold
        SUSPICIOUS_ROUND_AMOUNT    // Suspiciously round amounts (exactly $1000, $5000, etc)
    }

    public static class Result {
        private final Set<Rule> violations = new HashSet<>();
        private int riskScore = 0;

        public void add(Rule r, int scoreIncrease) {
            violations.add(r);
            riskScore += scoreIncrease;
            log.info("Added fraud rule violation: {} (risk score: +{}, total: {})", r, scoreIncrease, riskScore);
        }

        public void add(Rule r) {
            add(r, getRiskScore(r));
        }

        private int getRiskScore(Rule rule) {
            return switch (rule) {
                case NEW_ACCOUNT -> 25;
                case CHANGED_ACCOUNT -> 35;
                case IBAN_CHECKSUM_INVALID -> 50;
                case DUPLICATE_BANK_ACCOUNT -> 60;
                case SENDER_MISMATCH -> 30;
                case VELOCITY_ANOMALY -> 40;
                case AMOUNT_OUTLIER -> 45;
                case WEEKEND_SUBMISSION -> 15;
                case COUNTRY_MISMATCH -> 25;
                case AMOUNT_THRESHOLD_EXCEEDED -> 80;
                case SUSPICIOUS_ROUND_AMOUNT -> 20;
                case INVALID_FORMAT -> 30;
            };
        }

        public boolean flagged() {
            // Flag if risk score exceeds threshold OR has critical violations
            boolean isFlagged = riskScore >= 50 ||
                    violations.contains(Rule.IBAN_CHECKSUM_INVALID) ||
                    violations.contains(Rule.DUPLICATE_BANK_ACCOUNT) ||
                    violations.contains(Rule.AMOUNT_THRESHOLD_EXCEEDED);

            log.info("Fraud detection result: flagged={}, riskScore={}, violations={}",
                    isFlagged, riskScore, violations);
            return isFlagged;
        }

        public Set<Rule> getViolations() { return violations; }
        public int getRiskScore() { return riskScore; }
    }

    // Configuration for risk thresholds
    private static final BigDecimal HIGH_AMOUNT_THRESHOLD = new BigDecimal("50000.00");
    private static final Set<String> SUSPICIOUS_DOMAINS = Set.of(
            "tempmail.com", "10minutemail.com", "guerrillamail.com", "mailinator.com"
    );

    public Result evaluate(UUID tenantId, String vendorName, String bankLast4, String fullIban,
                           BigDecimal amount, String currency, Optional<String> senderDomain,
                           OffsetDateTime submissionTime, VendorHistoryRepository vendorRepo) {

        log.info("Starting ENHANCED fraud detection - tenant: {}, vendor: {}, amount: {} {}, iban: {}",
                tenantId, vendorName, amount, currency, fullIban != null ? fullIban.substring(0, 4) + "****" : "null");

        Result r = new Result();

        // EXISTING RULES (keep your current logic)
        evaluateExistingRules(tenantId, vendorName, bankLast4, senderDomain, vendorRepo, r);

        // NEW ENHANCED RULES
        evaluateIbanChecksum(fullIban, r);
        evaluateAmountPatterns(amount, currency, r);
        evaluateSubmissionTiming(submissionTime, r);
        evaluateSenderDomain(senderDomain, r);
        evaluateGeographicConsistency(fullIban, vendorName, r);

        // TODO: Add velocity checking (requires invoice history)
        // evaluateVelocityAnomalies(tenantId, vendorName, vendorRepo, r);

        log.info("Enhanced fraud detection completed - riskScore: {}, violations: {}",
                r.getRiskScore(), r.getViolations());
        return r;
    }

    private void evaluateExistingRules(UUID tenantId, String vendorName, String bankLast4,
                                       Optional<String> senderDomain, VendorHistoryRepository vendorRepo, Result r) {
        // Your existing logic - keep as is
        Optional<Vendor> existing = vendorRepo.findByName(tenantId, vendorName);

        if (existing.isEmpty()) {
            if (bankLast4 != null && !bankLast4.isBlank()) {
                r.add(Rule.NEW_ACCOUNT);
            }
        } else {
            Vendor vendor = existing.get();
            String existingLast4 = vendor.getCurrentBankLast4();

            if (bankLast4 != null && !bankLast4.isBlank()) {
                if (existingLast4 == null || existingLast4.isBlank()) {
                    r.add(Rule.CHANGED_ACCOUNT);
                } else if (!Objects.equals(existingLast4, bankLast4)) {
                    r.add(Rule.CHANGED_ACCOUNT);
                }
            }

            String expectedDomain = vendor.getEmailDomain();
            if (senderDomain.isPresent() && expectedDomain != null &&
                    !senderDomain.get().endsWith(expectedDomain)) {
                r.add(Rule.SENDER_MISMATCH);
            }
        }

        if (bankLast4 != null && bankLast4.length() != 4) {
            r.add(Rule.INVALID_FORMAT);
        }
    }

    /**
     * IBAN Checksum Validation using ISO 13616 standard
     * This catches many fraudulent IBANs with invalid check digits
     */
    private void evaluateIbanChecksum(String iban, Result r) {
        if (iban == null || iban.isBlank()) {
            log.debug("No IBAN provided, skipping checksum validation");
            return;
        }

        try {
            String cleanIban = iban.replaceAll("[\\s-]", "").toUpperCase();

            if (cleanIban.length() < 4 || !cleanIban.matches("[A-Z]{2}[0-9]{2}[A-Z0-9]+")) {
                log.warn("Invalid IBAN format: {}", iban);
                r.add(Rule.INVALID_FORMAT);
                return;
            }

            // ISO 13616 checksum algorithm
            if (!isValidIbanChecksum(cleanIban)) {
                log.warn("IBAN checksum validation failed for: {}", iban.substring(0, 4) + "****");
                r.add(Rule.IBAN_CHECKSUM_INVALID);
            } else {
                log.debug("IBAN checksum validation passed");
            }

        } catch (Exception e) {
            log.warn("IBAN validation error for {}: {}", iban, e.getMessage());
            r.add(Rule.INVALID_FORMAT);
        }
    }

    /**
     * ISO 13616 IBAN checksum validation algorithm
     */
    private boolean isValidIbanChecksum(String iban) {
        try {
            // Move first 4 characters to end
            String rearranged = iban.substring(4) + iban.substring(0, 4);

            // Replace letters with numbers (A=10, B=11, ..., Z=35)
            StringBuilder numeric = new StringBuilder();
            for (char c : rearranged.toCharArray()) {
                if (Character.isLetter(c)) {
                    numeric.append(c - 'A' + 10);
                } else {
                    numeric.append(c);
                }
            }

            // Calculate mod 97
            String numStr = numeric.toString();
            int remainder = 0;
            for (char digit : numStr.toCharArray()) {
                remainder = (remainder * 10 + Character.getNumericValue(digit)) % 97;
            }

            return remainder == 1;

        } catch (Exception e) {
            log.warn("IBAN checksum calculation error: {}", e.getMessage());
            return false;
        }
    }

    /**
     * Analyze amount patterns for suspicious activity
     */
    private void evaluateAmountPatterns(BigDecimal amount, String currency, Result r) {
        if (amount == null) {
            log.debug("No amount provided for pattern analysis");
            return;
        }

        // High amount threshold check
        if (amount.compareTo(HIGH_AMOUNT_THRESHOLD) > 0) {
            log.warn("Amount exceeds high-risk threshold: {} (threshold: {})", amount, HIGH_AMOUNT_THRESHOLD);
            r.add(Rule.AMOUNT_THRESHOLD_EXCEEDED);
        }

        // Suspicious round amounts (exactly $1000, $5000, $10000, etc.)
        if (isSuspiciouslyRoundAmount(amount)) {
            log.warn("Suspiciously round amount detected: {}", amount);
            r.add(Rule.SUSPICIOUS_ROUND_AMOUNT);
        }

        log.debug("Amount pattern analysis completed for: {} {}", amount, currency);
    }

    /**
     * Check for suspiciously round amounts that fraudsters often use
     */
    private boolean isSuspiciouslyRoundAmount(BigDecimal amount) {
        // Check if amount is exactly divisible by 1000 and >= 1000
        if (amount.compareTo(new BigDecimal("1000")) >= 0) {
            BigDecimal remainder = amount.remainder(new BigDecimal("1000"));
            return remainder.compareTo(BigDecimal.ZERO) == 0;
        }

        // Check for other suspicious patterns (exactly $500, $2500, etc.)
        BigDecimal[] suspiciousAmounts = {
                new BigDecimal("500.00"), new BigDecimal("2500.00"),
                new BigDecimal("7500.00"), new BigDecimal("12500.00")
        };

        for (BigDecimal suspicious : suspiciousAmounts) {
            if (amount.compareTo(suspicious) == 0) {
                return true;
            }
        }

        return false;
    }

    /**
     * Analyze submission timing for suspicious patterns
     */
    private void evaluateSubmissionTiming(OffsetDateTime submissionTime, Result r) {
        if (submissionTime == null) {
            submissionTime = OffsetDateTime.now();
        }

        LocalDateTime localTime = submissionTime.toLocalDateTime();
        DayOfWeek dayOfWeek = localTime.getDayOfWeek();
        int hourOfDay = localTime.getHour();

        // Flag weekend submissions (higher fraud risk)
        if (dayOfWeek == DayOfWeek.SATURDAY || dayOfWeek == DayOfWeek.SUNDAY) {
            log.warn("Weekend submission detected: {} at {}", dayOfWeek, localTime);
            r.add(Rule.WEEKEND_SUBMISSION);
        }

        // Flag late night submissions (00:00 - 05:00)
        if (hourOfDay >= 0 && hourOfDay <= 5) {
            log.warn("Late night submission detected: {} at {}:00", dayOfWeek, hourOfDay);
            r.add(Rule.WEEKEND_SUBMISSION); // Use same rule for now
        }

        log.debug("Timing analysis completed - day: {}, hour: {}", dayOfWeek, hourOfDay);
    }

    /**
     * Evaluate sender domain reputation and patterns
     */
    private void evaluateSenderDomain(Optional<String> senderDomain, Result r) {
        if (senderDomain.isEmpty()) {
            log.debug("No sender domain provided for reputation analysis");
            return;
        }

        String domain = senderDomain.get().toLowerCase();

        // Check against known suspicious domains
        if (SUSPICIOUS_DOMAINS.contains(domain)) {
            log.warn("Suspicious sender domain detected: {}", domain);
            r.add(Rule.SENDER_MISMATCH);
        }

        // Check for temporary email patterns
        if (domain.contains("temp") || domain.contains("10min") || domain.contains("disposable")) {
            log.warn("Temporary email domain pattern detected: {}", domain);
            r.add(Rule.SENDER_MISMATCH);
        }

        // Check for suspicious TLD patterns
        String[] suspiciousTlds = {".tk", ".ml", ".ga", ".cf"};
        for (String tld : suspiciousTlds) {
            if (domain.endsWith(tld)) {
                log.warn("Suspicious TLD detected: {} ends with {}", domain, tld);
                r.add(Rule.SENDER_MISMATCH);
                break;
            }
        }

        log.debug("Domain reputation analysis completed for: {}", domain);
    }

    /**
     * Check geographic consistency between IBAN country and vendor location
     */
    private void evaluateGeographicConsistency(String iban, String vendorName, Result r) {
        if (iban == null || iban.length() < 2) {
            log.debug("No IBAN country code available for geographic analysis");
            return;
        }

        String ibanCountry = iban.substring(0, 2).toUpperCase();

        // Simple heuristic: check if vendor name suggests different country
        Map<String, String> countryIndicators = Map.of(
                "US", "LLC|Inc|Corp|Corporation",
                "GB", "Ltd|Limited|PLC",
                "DE", "GmbH|AG",
                "FR", "SARL|SA|SAS",
                "IT", "SRL|SpA"
        );

        for (Map.Entry<String, String> entry : countryIndicators.entrySet()) {
            String country = entry.getKey();
            String pattern = entry.getValue();

            if (!country.equals(ibanCountry) && vendorName.matches(".*(" + pattern + ").*")) {
                log.warn("Geographic mismatch: IBAN country {} but vendor name suggests {}: {}",
                        ibanCountry, country, vendorName);
                r.add(Rule.COUNTRY_MISMATCH);
                break;
            }
        }

        log.debug("Geographic consistency check completed - IBAN country: {}", ibanCountry);
    }

    /**
     * Future enhancement: Velocity anomaly detection
     * Requires access to invoice history for the vendor
     */
    private void evaluateVelocityAnomalies(UUID tenantId, String vendorName,
                                           VendorHistoryRepository vendorRepo, Result r) {
        // TODO: Implement when invoice history queries are available
        // Check for:
        // - More than 5 invoices from same vendor in 24 hours
        // - More than 10 invoices in a week
        // - Sudden spike in invoice frequency

        log.debug("Velocity analysis not yet implemented - requires invoice history queries");
    }

    /**
     * Enhanced wrapper that maintains backward compatibility
     */
    public Result evaluate(UUID tenantId, String vendorName, String bankLast4, Optional<String> senderDomain,
                           VendorHistoryRepository vendorRepo) {
        // Call enhanced version with default values
        return evaluate(tenantId, vendorName, bankLast4, null, null, null, senderDomain,
                OffsetDateTime.now(), vendorRepo);
    }

    /**
     * NEW: Enhanced evaluation with full invoice data
     */
    public Result evaluate(UUID tenantId, String vendorName, String bankLast4, String fullIban,
                           BigDecimal amount, String currency, Optional<String> senderDomain,
                           OffsetDateTime submissionTime, VendorHistoryRepository vendorRepo) {

        log.info("Starting ENHANCED fraud detection - tenant: {}, vendor: {}, amount: {} {}",
                tenantId, vendorName, amount, currency);

        Result r = new Result();

        // Run existing fraud detection logic
        evaluateExistingRules(tenantId, vendorName, bankLast4, senderDomain, vendorRepo, r);

        // Run new enhanced rules
        evaluateIbanChecksum(fullIban, r);
        evaluateAmountPatterns(amount, currency, r);
        evaluateSubmissionTiming(submissionTime, r);
        evaluateSenderDomain(senderDomain, r);
        evaluateGeographicConsistency(fullIban, vendorName, r);

        log.info("Enhanced fraud detection completed - finalRiskScore: {}, violations: {}",
                r.getRiskScore(), r.getViolations());
        return r;
    }

    private void evaluateExistingRules(UUID tenantId, String vendorName, String bankLast4,
                                       Optional<String> senderDomain, VendorHistoryRepository vendorRepo, Result r) {
        // Your existing DetectionEngine logic goes here
        Optional<Vendor> existing = vendorRepo.findByName(tenantId, vendorName);

        if (existing.isEmpty()) {
            if (bankLast4 != null && !bankLast4.isBlank()) {
                r.add(Rule.NEW_ACCOUNT);
            }
        } else {
            Vendor vendor = existing.get();
            String existingLast4 = vendor.getCurrentBankLast4();

            if (bankLast4 != null && !bankLast4.isBlank()) {
                if (existingLast4 == null || existingLast4.isBlank()) {
                    r.add(Rule.CHANGED_ACCOUNT);
                } else if (!Objects.equals(existingLast4, bankLast4)) {
                    r.add(Rule.CHANGED_ACCOUNT);
                }
            }

            String expectedDomain = vendor.getEmailDomain();
            if (senderDomain.isPresent() && expectedDomain != null &&
                    !senderDomain.get().endsWith(expectedDomain)) {
                r.add(Rule.SENDER_MISMATCH);
            }
        }

        if (bankLast4 != null && bankLast4.length() != 4) {
            r.add(Rule.INVALID_FORMAT);
        }
    }

    /**
     * Risk assessment summary for reporting
     */
    public static class RiskAssessment {
        public final int riskScore;
        public final String riskLevel;
        public final Set<Rule> violations;
        public final String recommendation;

        public RiskAssessment(Result result) {
            this.riskScore = result.getRiskScore();
            this.violations = result.getViolations();

            if (riskScore >= 80) {
                this.riskLevel = "CRITICAL";
                this.recommendation = "REJECT - High fraud probability";
            } else if (riskScore >= 50) {
                this.riskLevel = "HIGH";
                this.recommendation = "MANUAL_REVIEW - Multiple risk factors";
            } else if (riskScore >= 25) {
                this.riskLevel = "MEDIUM";
                this.recommendation = "ENHANCED_VERIFICATION - Some concerns";
            } else {
                this.riskLevel = "LOW";
                this.recommendation = "APPROVE - Minimal risk detected";
            }
        }
    }

    public RiskAssessment assessRisk(Result result) {
        return new RiskAssessment(result);
    }
}