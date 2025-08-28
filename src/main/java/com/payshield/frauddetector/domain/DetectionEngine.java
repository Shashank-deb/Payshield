package com.payshield.frauddetector.domain;

import com.payshield.frauddetector.domain.ports.VendorHistoryRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.HashSet;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

public class DetectionEngine {

    private static final Logger log = LoggerFactory.getLogger(DetectionEngine.class);

    public enum Rule {
        NEW_ACCOUNT,
        CHANGED_ACCOUNT,
        INVALID_FORMAT,
        SENDER_MISMATCH
    }

    public static class Result {
        private final Set<Rule> violations = new HashSet<>();

        public void add(Rule r) {
            violations.add(r);
            log.info("Added fraud rule violation: {}", r);
        }

        public boolean flagged() {
            boolean isFlagged = !violations.isEmpty();
            log.info("Fraud detection result: flagged={}, violations={}", isFlagged, violations);
            return isFlagged;
        }

        public Set<Rule> getViolations() {
            return violations;
        }
    }

    public Result evaluate(UUID tenantId, String vendorName, String bankLast4, Optional<String> senderDomain, VendorHistoryRepository vendorRepo) {
        log.info("Starting fraud detection evaluation - tenantId: {}, vendor: {}, bankLast4: {}, senderDomain: {}",
                tenantId, vendorName, bankLast4, senderDomain.orElse("none"));

        Result r = new Result();

        // Check if vendor exists
        Optional<Vendor> existing = vendorRepo.findByName(tenantId, vendorName);
        log.info("Vendor lookup result - exists: {}", existing.isPresent());

        if (existing.isEmpty()) {
            log.info("New vendor detected: {}", vendorName);

            // NEW_ACCOUNT rule: new vendor with bank account
            if (bankLast4 != null && !bankLast4.isBlank()) {
                log.info("New vendor has bank account details ({}), triggering NEW_ACCOUNT rule", bankLast4);
                r.add(Rule.NEW_ACCOUNT);
            } else {
                log.info("New vendor but no bank account details found");
            }
        } else {
            log.info("Existing vendor found, checking for account changes");
            Vendor vendor = existing.get();
            String existingLast4 = vendor.getCurrentBankLast4();

            log.info("Existing vendor bank account: '{}', New bank account: '{}'", existingLast4, bankLast4);

            // CHANGED_ACCOUNT rule: Fix the null comparison logic
            if (bankLast4 != null && !bankLast4.isBlank()) {
                // Case 1: Existing account is null/blank, new account has value
                if (existingLast4 == null || existingLast4.isBlank()) {
                    log.info("Bank account added: null/empty -> {}, triggering CHANGED_ACCOUNT rule", bankLast4);
                    r.add(Rule.CHANGED_ACCOUNT);
                }
                // Case 2: Both have values but they're different
                else if (!Objects.equals(existingLast4, bankLast4)) {
                    log.info("Bank account changed from {} to {}, triggering CHANGED_ACCOUNT rule", existingLast4, bankLast4);
                    r.add(Rule.CHANGED_ACCOUNT);
                }
                // Case 3: Same bank account
                else {
                    log.info("Bank account unchanged: {}", bankLast4);
                }
            }

            // SENDER_MISMATCH rule: email domain doesn't match expected
            String expectedDomain = vendor.getEmailDomain();
            if (senderDomain.isPresent() && expectedDomain != null && !senderDomain.get().endsWith(expectedDomain)) {
                log.info("Sender domain mismatch. Expected: {}, Got: {}, triggering SENDER_MISMATCH rule",
                        expectedDomain, senderDomain.get());
                r.add(Rule.SENDER_MISMATCH);
            }
        }

        // INVALID_FORMAT rule: bank account format validation
        if (bankLast4 != null && bankLast4.length() != 4) {
            log.info("Invalid bank account format: '{}' (length: {}), triggering INVALID_FORMAT rule",
                    bankLast4, bankLast4.length());
            r.add(Rule.INVALID_FORMAT);
        }

        log.info("Fraud detection evaluation completed - violations: {}", r.getViolations());
        return r;
    }
}