package com.payshield.frauddetector.infrastructure.jpa;

import jakarta.persistence.*;
import java.time.OffsetDateTime;
import java.util.UUID;

@Entity
@Table(name = "mfa_configuration")
public class MfaConfigurationEntity {

    @Id
    @Column(name = "user_id")
    private UUID userId;

    @Column(name = "tenant_id", nullable = false)
    private UUID tenantId;

    @Column(name = "encrypted_secret", columnDefinition = "TEXT")
    private String encryptedSecret;

    @Column(name = "secret_hash", length = 64)
    private String secretHash;

    @Column(nullable = false, length = 20)
    @Enumerated(EnumType.STRING)
    private MfaStatusType status = MfaStatusType.PENDING;

    @Column(name = "is_setup_complete", nullable = false)
    private boolean isSetupComplete = false;

    @Column(name = "setup_completed_at")
    private OffsetDateTime setupCompletedAt;

    @Column(name = "last_used_at")
    private OffsetDateTime lastUsedAt;

    @Column(name = "failed_attempts", nullable = false)
    private int failedAttempts = 0;

    @Column(name = "locked_until")
    private OffsetDateTime lockedUntil;

    @Column(name = "backup_codes_remaining", nullable = false)
    private int backupCodesRemaining = 0;

    @Column(name = "backup_codes_generated_at")
    private OffsetDateTime backupCodesGeneratedAt;

    @Column(name = "encryption_key_version", nullable = false)
    private int encryptionKeyVersion = 1;

    @Column(name = "created_at", nullable = false)
    private OffsetDateTime createdAt = OffsetDateTime.now();

    @Column(name = "updated_at", nullable = false)
    private OffsetDateTime updatedAt = OffsetDateTime.now();

    // Constructors
    public MfaConfigurationEntity() {}

    // Getters and Setters
    public UUID getUserId() { return userId; }
    public void setUserId(UUID userId) { this.userId = userId; }

    public UUID getTenantId() { return tenantId; }
    public void setTenantId(UUID tenantId) { this.tenantId = tenantId; }

    public String getEncryptedSecret() { return encryptedSecret; }
    public void setEncryptedSecret(String encryptedSecret) { this.encryptedSecret = encryptedSecret; }

    public String getSecretHash() { return secretHash; }
    public void setSecretHash(String secretHash) { this.secretHash = secretHash; }

    public MfaStatusType getStatus() { return status; }
    public void setStatus(MfaStatusType status) { this.status = status; }

    public boolean isSetupComplete() { return isSetupComplete; }
    public void setSetupComplete(boolean setupComplete) { isSetupComplete = setupComplete; }

    public OffsetDateTime getSetupCompletedAt() { return setupCompletedAt; }
    public void setSetupCompletedAt(OffsetDateTime setupCompletedAt) { this.setupCompletedAt = setupCompletedAt; }

    public OffsetDateTime getLastUsedAt() { return lastUsedAt; }
    public void setLastUsedAt(OffsetDateTime lastUsedAt) { this.lastUsedAt = lastUsedAt; }

    public int getFailedAttempts() { return failedAttempts; }
    public void setFailedAttempts(int failedAttempts) { this.failedAttempts = failedAttempts; }

    public OffsetDateTime getLockedUntil() { return lockedUntil; }
    public void setLockedUntil(OffsetDateTime lockedUntil) { this.lockedUntil = lockedUntil; }

    public int getBackupCodesRemaining() { return backupCodesRemaining; }
    public void setBackupCodesRemaining(int backupCodesRemaining) { this.backupCodesRemaining = backupCodesRemaining; }

    public OffsetDateTime getBackupCodesGeneratedAt() { return backupCodesGeneratedAt; }
    public void setBackupCodesGeneratedAt(OffsetDateTime backupCodesGeneratedAt) { this.backupCodesGeneratedAt = backupCodesGeneratedAt; }

    public int getEncryptionKeyVersion() { return encryptionKeyVersion; }
    public void setEncryptionKeyVersion(int encryptionKeyVersion) { this.encryptionKeyVersion = encryptionKeyVersion; }

    public OffsetDateTime getCreatedAt() { return createdAt; }
    public void setCreatedAt(OffsetDateTime createdAt) { this.createdAt = createdAt; }

    public OffsetDateTime getUpdatedAt() { return updatedAt; }
    public void setUpdatedAt(OffsetDateTime updatedAt) { this.updatedAt = updatedAt; }

    @PreUpdate
    public void preUpdate() {
        this.updatedAt = OffsetDateTime.now();
    }

    public enum MfaStatusType {
        PENDING, ENABLED, DISABLED, LOCKED
    }
}
