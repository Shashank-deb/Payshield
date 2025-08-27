package com.payshield.frauddetector.domain;

import com.payshield.frauddetector.domain.ports.VendorHistoryRepository;

import java.util.HashSet;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

public class DetectionEngine {

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
        }

        public boolean flagged() {
            return !violations.isEmpty();
        }

        public Set<Rule> getViolations() {
            return violations;
        }

    }


    public Result evaluate(UUID tenantId, String vendorName, String bankLast4, Optional<String> senderDomain, VendorHistoryRepository vendorRepo) {
        Result r = new Result();
        Optional<Vendor> existing = vendorRepo.findByName(tenantId, vendorName);
        if (existing.isEmpty()) {
            if (bankLast4 != null && !bankLast4.isBlank()) r.add(Rule.NEW_ACCOUNT);
        } else {
            String last4 = existing.get().getCurrentBankLast4();
            if (last4 != null && bankLast4 != null && !bankLast4.equals(last4)) r.add(Rule.CHANGED_ACCOUNT);
            String expectedDomain = existing.get().getEmailDomain();
            if (senderDomain.isPresent() && expectedDomain != null && !senderDomain.get().endsWith(expectedDomain))
                r.add(Rule.SENDER_MISMATCH);
        }
        if (bankLast4 != null && bankLast4.length() != 4) r.add(Rule.INVALID_FORMAT);
        return r;


    }
}
