package com.payshield.frauddetector.domain;

import java.util.UUID;

public class Vendor {

    private final UUID id;
    private final UUID tenantId;
    private final String name;
    private final String emailDomain;
    private final String currentBankLast4;

    public Vendor(UUID id, UUID tenantId, String name, String emailDomain, String currentBankLast4) {
        this.id = id;
        this.tenantId = tenantId;
        this.name = name;
        this.emailDomain = emailDomain;
        this.currentBankLast4 = currentBankLast4;
    }


    public UUID getId() {
        return id;
    }

    public UUID getTenantId() {
        return tenantId;
    }

    public String getName() {
        return name;
    }

    public String getEmailDomain() {
        return emailDomain;
    }

    public String getCurrentBankLast4() {
        return currentBankLast4;
    }
}
