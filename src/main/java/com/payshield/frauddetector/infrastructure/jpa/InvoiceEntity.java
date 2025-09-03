package com.payshield.frauddetector.infrastructure.jpa;
import jakarta.persistence.*;
import java.math.BigDecimal;
import java.time.OffsetDateTime;
import java.util.UUID;

@Entity
@Table(name = "invoice")
public class InvoiceEntity {

    @Id
    private UUID id;

    @Column(name = "tenant_id", nullable = false)
    private UUID tenantId;

    @Column(name = "vendor_id", nullable = false)
    private UUID vendorId;

    @Column(name = "received_at", nullable = false)
    private OffsetDateTime receivedAt;

    @Column(precision = 18, scale = 2)
    private BigDecimal amount;

    @Column(length = 3)
    private String currency;

    @Column(name = "bank_iban")
    private String bankIban;

    @Column(name = "bank_swift")
    private String bankSwift;

    @Column(name = "bank_last4")
    private String bankLast4;

    @Column(name = "source_message_id")
    private String sourceMessageId;

    @Column(name = "file_sha256")
    private String fileSha256;

    // Standard getters and setters
    public UUID getId() { return id; }
    public void setId(UUID id) { this.id = id; }

    public UUID getTenantId() { return tenantId; }
    public void setTenantId(UUID tenantId) { this.tenantId = tenantId; }

    public UUID getVendorId() { return vendorId; }
    public void setVendorId(UUID vendorId) { this.vendorId = vendorId; }

    public OffsetDateTime getReceivedAt() { return receivedAt; }
    public void setReceivedAt(OffsetDateTime receivedAt) { this.receivedAt = receivedAt; }

    public BigDecimal getAmount() { return amount; }
    public void setAmount(BigDecimal amount) { this.amount = amount; }

    public String getCurrency() { return currency; }
    public void setCurrency(String currency) { this.currency = currency; }

    public String getBankIban() { return bankIban; }
    public void setBankIban(String bankIban) { this.bankIban = bankIban; }

    public String getBankSwift() { return bankSwift; }
    public void setBankSwift(String bankSwift) { this.bankSwift = bankSwift; }

    public String getBankLast4() { return bankLast4; }
    public void setBankLast4(String bankLast4) { this.bankLast4 = bankLast4; }

    public String getSourceMessageId() { return sourceMessageId; }
    public void setSourceMessageId(String sourceMessageId) { this.sourceMessageId = sourceMessageId; }

    public String getFileSha256() { return fileSha256; }
    public void setFileSha256(String fileSha256) { this.fileSha256 = fileSha256; }
}