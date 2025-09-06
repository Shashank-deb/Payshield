// ==============================================================================
// MFA Configuration Domain Model
// File: src/main/java/com/payshield/frauddetector/domain/mfa/MfaConfiguration.java
// ==============================================================================

package com.payshield.frauddetector.domain.mfa;

import java.time.OffsetDateTime;
import java.util.UUID;

/**
 * Domain model representing a user's MFA configuration and state
 */
public class MfaConfiguration {
    private final UUID userId;
    private final UUID tenantId;
    private final String encryptedSecret;
    private final String secretHash;
    private final MfaStatus status;
    private final boolean isSetupComplete;
    private final OffsetDateTime setupCompletedAt;
    private final OffsetDateTime lastUsedAt;
    private final int failedAttempts;
    private final OffsetDateTime lockedUntil;
    private final int backupCodesRemaining;
    private final OffsetDateTime backupCodesGeneratedAt;
    private final int encryptionKeyVersion;
    private final OffsetDateTime createdAt;
    private final OffsetDateTime updatedAt;

    public MfaConfiguration(UUID userId, UUID tenantId, String encryptedSecret, String secretHash,
                           MfaStatus status, boolean isSetupComplete, OffsetDateTime setupCompletedAt,
                           OffsetDateTime lastUsedAt, int failedAttempts, OffsetDateTime lockedUntil,
                           int backupCodesRemaining, OffsetDateTime backupCodesGeneratedAt,
                           int encryptionKeyVersion, OffsetDateTime createdAt, OffsetDateTime updatedAt) {
        this.userId = userId;
        this.tenantId = tenantId;
        this.encryptedSecret = encryptedSecret;
        this.secretHash = secretHash;
        this.status = status;
        this.isSetupComplete = isSetupComplete;
        this.setupCompletedAt = setupCompletedAt;
        this.lastUsedAt = lastUsedAt;
        this.failedAttempts = failedAttempts;
        this.lockedUntil = lockedUntil;
        this.backupCodesRemaining = backupCodesRemaining;
        this.backupCodesGeneratedAt = backupCodesGeneratedAt;
        this.encryptionKeyVersion = encryptionKeyVersion;
        this.createdAt = createdAt;
        this.updatedAt = updatedAt;
    }

    // Getters
    public UUID getUserId() { return userId; }
    public UUID getTenantId() { return tenantId; }
    public String getEncryptedSecret() { return encryptedSecret; }
    public String getSecretHash() { return secretHash; }
    public MfaStatus getStatus() { return status; }
    public boolean isSetupComplete() { return isSetupComplete; }
    public OffsetDateTime getSetupCompletedAt() { return setupCompletedAt; }
    public OffsetDateTime getLastUsedAt() { return lastUsedAt; }
    public int getFailedAttempts() { return failedAttempts; }
    public OffsetDateTime getLockedUntil() { return lockedUntil; }
    public int getBackupCodesRemaining() { return backupCodesRemaining; }
    public OffsetDateTime getBackupCodesGeneratedAt() { return backupCodesGeneratedAt; }
    public int getEncryptionKeyVersion() { return encryptionKeyVersion; }
    public OffsetDateTime getCreatedAt() { return createdAt; }
    public OffsetDateTime getUpdatedAt() { return updatedAt; }

    // Business logic methods
    public boolean isLocked() {
        return status == MfaStatus.LOCKED || 
               (lockedUntil != null && lockedUntil.isAfter(OffsetDateTime.now()));
    }

    public boolean isEnabled() {
        return status == MfaStatus.ENABLED && isSetupComplete && !isLocked();
    }

    public boolean canAttemptAuthentication() {
        return isEnabled() && !isLocked();
    }

    public boolean requiresSetup() {
        return status == MfaStatus.PENDING || !isSetupComplete;
    }

    public boolean hasBackupCodes() {
        return backupCodesRemaining > 0;
    }
}