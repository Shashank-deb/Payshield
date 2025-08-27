package com.payshield.frauddetector.domain;

import java.math.BigDecimal;
import java.time.OffsetDateTime;
import java.util.UUID;

public class Invoice {

    private final UUID id;
    private final UUID tenantId;
    private final UUID vendorId;
    private final OffsetDateTime receivedAt;
    private final BigDecimal amount;
    private final String currency;
    private final String bankIban;
    private final String bankSwift;
    private final String bankLast4;
    private final String sourceMessageId;
    private final String fileSha256;

    public Invoice(UUID id, UUID tenantId, UUID vendorId, OffsetDateTime receivedAt, BigDecimal amount, String currency, String bankIban, String bankSwift, String bankLast4, String sourceMessageId, String fileSha256) {
        this.id = id;
        this.tenantId = tenantId;
        this.vendorId = vendorId;
        this.receivedAt = receivedAt;
        this.amount = amount;
        this.currency = currency;
        this.bankIban = bankIban;
        this.bankSwift = bankSwift;
        this.bankLast4 = bankLast4;
        this.sourceMessageId = sourceMessageId;
        this.fileSha256 = fileSha256;
    }

    public UUID getId() {
        return id;
    }

    public UUID getTenantId() {
        return tenantId;
    }

    public UUID getVendorId() {
        return vendorId;
    }

    public OffsetDateTime getReceivedAt() {
        return receivedAt;
    }

    public BigDecimal getAmount() {
        return amount;
    }

    public String getCurrency() {
        return currency;
    }

    public String getBankIban() {
        return bankIban;
    }

    public String getBankSwift() {
        return bankSwift;
    }

    public String getBankLast4() {
        return bankLast4;
    }

    public String getSourceMessageId() {
        return sourceMessageId;
    }

    public String getFileSha256() {
        return fileSha256;
    }
}
