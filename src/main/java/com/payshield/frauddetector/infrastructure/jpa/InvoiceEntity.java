// ==============================================================================
// Step 2B: Updated Invoice Entity with Encryption Support
// Replace: src/main/java/com/payshield/frauddetector/infrastructure/jpa/InvoiceEntity.java
// ==============================================================================

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

    // ==============================================================================
    // LEGACY PLAINTEXT FIELDS (deprecated but kept for migration compatibility)
    // ==============================================================================
    @Column(name = "bank_iban")
    @Deprecated(since = "2.0", forRemoval = true)
    private String bankIban;

    @Column(name = "bank_swift")
    @Deprecated(since = "2.0", forRemoval = true)
    private String bankSwift;

    @Column(name = "bank_last4")
    private String bankLast4; // Keep plaintext for searching/display

    // ==============================================================================
    // NEW ENCRYPTED FIELDS (from V4 migration)
    // ==============================================================================
    @Column(name = "bank_iban_encrypted", columnDefinition = "TEXT")
    private String bankIbanEncrypted;

    @Column(name = "bank_swift_encrypted", columnDefinition = "TEXT")
    private String bankSwiftEncrypted;

    @Column(name = "bank_iban_hash", length = 64)
    private String bankIbanHash; // SHA-256 hash for duplicate detection

    // ==============================================================================
    // OTHER FIELDS
    // ==============================================================================
    @Column(name = "source_message_id")
    private String sourceMessageId;

    @Column(name = "file_sha256")
    private String fileSha256;

    // ==============================================================================
    // CONSTRUCTORS
    // ==============================================================================
    public InvoiceEntity() {}

    // ==============================================================================
    // STANDARD GETTERS AND SETTERS
    // ==============================================================================
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

    public String getBankLast4() { return bankLast4; }
    public void setBankLast4(String bankLast4) { this.bankLast4 = bankLast4; }

    public String getSourceMessageId() { return sourceMessageId; }
    public void setSourceMessageId(String sourceMessageId) { this.sourceMessageId = sourceMessageId; }

    public String getFileSha256() { return fileSha256; }
    public void setFileSha256(String fileSha256) { this.fileSha256 = fileSha256; }

    // ==============================================================================
    // LEGACY PLAINTEXT FIELD GETTERS/SETTERS (deprecated)
    // ==============================================================================
    @Deprecated(since = "2.0", forRemoval = true)
    public String getBankIban() { return bankIban; }

    @Deprecated(since = "2.0", forRemoval = true)
    public void setBankIban(String bankIban) { this.bankIban = bankIban; }

    @Deprecated(since = "2.0", forRemoval = true)
    public String getBankSwift() { return bankSwift; }

    @Deprecated(since = "2.0", forRemoval = true)
    public void setBankSwift(String bankSwift) { this.bankSwift = bankSwift; }

    // ==============================================================================
    // ENCRYPTED FIELD GETTERS/SETTERS
    // ==============================================================================
    public String getBankIbanEncrypted() { return bankIbanEncrypted; }
    public void setBankIbanEncrypted(String bankIbanEncrypted) { this.bankIbanEncrypted = bankIbanEncrypted; }

    public String getBankSwiftEncrypted() { return bankSwiftEncrypted; }
    public void setBankSwiftEncrypted(String bankSwiftEncrypted) { this.bankSwiftEncrypted = bankSwiftEncrypted; }

    public String getBankIbanHash() { return bankIbanHash; }
    public void setBankIbanHash(String bankIbanHash) { this.bankIbanHash = bankIbanHash; }

    // ==============================================================================
    // CONVENIENCE METHODS FOR ENCRYPTION/DECRYPTION
    // ==============================================================================

    /**
     * Check if this entity uses encrypted storage
     */
    public boolean hasEncryptedData() {
        return bankIbanEncrypted != null || bankSwiftEncrypted != null;
    }

    /**
     * Check if this entity still uses legacy plaintext storage
     */
    public boolean hasLegacyData() {
        return bankIban != null || bankSwift != null;
    }

    @Override
    public String toString() {
        return "InvoiceEntity{" +
                "id=" + id +
                ", tenantId=" + tenantId +
                ", vendorId=" + vendorId +
                ", receivedAt=" + receivedAt +
                ", amount=" + amount +
                ", currency='" + currency + '\'' +
                ", bankLast4='" + bankLast4 + '\'' +
                ", hasEncryptedData=" + hasEncryptedData() +
                ", hasLegacyData=" + hasLegacyData() +
                ", fileSha256='" + fileSha256 + '\'' +
                '}';
    }
}