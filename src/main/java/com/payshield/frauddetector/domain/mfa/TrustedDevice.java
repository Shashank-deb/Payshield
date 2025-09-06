// ==============================================================================
// Trusted Device Domain Model
// File: src/main/java/com/payshield/frauddetector/domain/mfa/TrustedDevice.java
// ==============================================================================

package com.payshield.frauddetector.domain.mfa;

import java.time.OffsetDateTime;
import java.util.UUID;

/**
 * Domain model representing a device trusted for MFA bypass
 */
public class TrustedDevice {
    private final UUID id;
    private final UUID userId;
    private final UUID tenantId;
    private final String deviceFingerprint;
    private final String deviceName;
    private final String userAgent;
    private final String ipAddress;
    private final String location;
    private final boolean isTrusted;
    private final OffsetDateTime trustedAt;
    private final OffsetDateTime expiresAt;
    private final OffsetDateTime lastSeenAt;
    private final OffsetDateTime revokedAt;
    private final UUID revokedBy;
    private final OffsetDateTime createdAt;

    public TrustedDevice(UUID id, UUID userId, UUID tenantId, String deviceFingerprint, String deviceName,
                        String userAgent, String ipAddress, String location, boolean isTrusted,
                        OffsetDateTime trustedAt, OffsetDateTime expiresAt, OffsetDateTime lastSeenAt,
                        OffsetDateTime revokedAt, UUID revokedBy, OffsetDateTime createdAt) {
        this.id = id;
        this.userId = userId;
        this.tenantId = tenantId;
        this.deviceFingerprint = deviceFingerprint;
        this.deviceName = deviceName;
        this.userAgent = userAgent;
        this.ipAddress = ipAddress;
        this.location = location;
        this.isTrusted = isTrusted;
        this.trustedAt = trustedAt;
        this.expiresAt = expiresAt;
        this.lastSeenAt = lastSeenAt;
        this.revokedAt = revokedAt;
        this.revokedBy = revokedBy;
        this.createdAt = createdAt;
    }

    // Getters
    public UUID getId() { return id; }
    public UUID getUserId() { return userId; }
    public UUID getTenantId() { return tenantId; }
    public String getDeviceFingerprint() { return deviceFingerprint; }
    public String getDeviceName() { return deviceName; }
    public String getUserAgent() { return userAgent; }
    public String getIpAddress() { return ipAddress; }
    public String getLocation() { return location; }
    public boolean isTrusted() { return isTrusted; }
    public OffsetDateTime getTrustedAt() { return trustedAt; }
    public OffsetDateTime getExpiresAt() { return expiresAt; }
    public OffsetDateTime getLastSeenAt() { return lastSeenAt; }
    public OffsetDateTime getRevokedAt() { return revokedAt; }
    public UUID getRevokedBy() { return revokedBy; }
    public OffsetDateTime getCreatedAt() { return createdAt; }

    // Business logic methods
    public boolean isCurrentlyTrusted() {
        if (!isTrusted || revokedAt != null) {
            return false;
        }
        
        if (expiresAt != null && expiresAt.isBefore(OffsetDateTime.now())) {
            return false;
        }
        
        return true;
    }

    public boolean isExpired() {
        return expiresAt != null && expiresAt.isBefore(OffsetDateTime.now());
    }

    public boolean isRevoked() {
        return revokedAt != null;
    }
}