package com.payshield.frauddetector.domain;

import java.time.OffsetDateTime;
import java.util.UUID;

public class CaseRecord {

    private final UUID id;
    private final UUID tenantId;
    private final UUID invoiceId;
    private final CaseState state;
    private final OffsetDateTime createdAt;


    public CaseRecord(UUID id, UUID tenantId, UUID invoiceId, CaseState state, OffsetDateTime createdAt) {
        this.id = id;
        this.tenantId = tenantId;
        this.invoiceId = invoiceId;
        this.state = state;
        this.createdAt = createdAt;
    }


    public UUID getId() {
        return id;
    }

    public UUID getTenantId() {
        return tenantId;
    }

    public UUID getInvoiceId() {
        return invoiceId;
    }

    public CaseState getState() {
        return state;
    }

    public OffsetDateTime getCreatedAt() {
        return createdAt;
    }
}