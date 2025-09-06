package com.payshield.frauddetector.infrastructure.jpa;

import jakarta.persistence.*;
import java.time.OffsetDateTime;
import java.util.UUID;

@Entity
@Table(name = "mfa_backup_codes")
public class MfaBackupCodeEntity {

    @Id
    private UUID id = UUID.randomUUID();

    @Column(name = "user_id", nullable = false)
    private UUID userId;

    @Column(name = "tenant_id", nullable = false)
    private UUID tenantId;

    @Column(name = "encrypted_code", nullable = false, columnDefinition = "TEXT")
    private String encryptedCode;

    @Column(name = "code_hash", nullable = false, length = 64)
    private String codeHash;

    @Column(name = "is_used", nullable = false)
    private boolean isUsed = false;

    @Column(name = "used_at")
    private OffsetDateTime usedAt;

    @Column(name = "used_from_ip")
    private String usedFromIp;

    @Column(name = "encryption_key_version", nullable = false)
    private int encryptionKeyVersion = 1;

    @Column(name = "created_at", nullable = false)
    private OffsetDateTime createdAt = OffsetDateTime.now();

    // Constructors
    public MfaBackupCodeEntity() {}

    // Getters and Setters
    public UUID getId() { return id; }
    public void setId(UUID id) { this.id = id; }

    public UUID getUserId() { return userId; }
    public void setUserId(UUID userId) { this.userId = userId; }

    public UUID getTenantId() { return tenantId; }
    public void setTenantId(UUID tenantId) { this.tenantId = tenantId; }

    public String getEncryptedCode() { return encryptedCode; }
    public void setEncryptedCode(String encryptedCode) { this.encryptedCode = encryptedCode; }

    public String getCodeHash() { return codeHash; }
    public void setCodeHash(String codeHash) { this.codeHash = codeHash; }

    public boolean isUsed() { return isUsed; }
    public void setUsed(boolean used) { isUsed = used; }

    public OffsetDateTime getUsedAt() { return usedAt; }
    public void setUsedAt(OffsetDateTime usedAt) { this.usedAt = usedAt; }

    public String getUsedFromIp() { return usedFromIp; }
    public void setUsedFromIp(String usedFromIp) { this.usedFromIp = usedFromIp; }

    public int getEncryptionKeyVersion() { return encryptionKeyVersion; }
    public void setEncryptionKeyVersion(int encryptionKeyVersion) { this.encryptionKeyVersion = encryptionKeyVersion; }

    public OffsetDateTime getCreatedAt() { return createdAt; }
    public void setCreatedAt(OffsetDateTime createdAt) { this.createdAt = createdAt; }
}