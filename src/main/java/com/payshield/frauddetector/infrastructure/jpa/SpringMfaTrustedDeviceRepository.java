// ==============================================================================
// MFA Trusted Device Repository
// File: src/main/java/com/payshield/frauddetector/infrastructure/jpa/SpringMfaTrustedDeviceRepository.java
// ==============================================================================

package com.payshield.frauddetector.infrastructure.jpa;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.OffsetDateTime;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface SpringMfaTrustedDeviceRepository extends JpaRepository<MfaTrustedDeviceEntity, UUID> {

    List<MfaTrustedDeviceEntity> findByUserIdAndTenantId(UUID userId, UUID tenantId);

    Optional<MfaTrustedDeviceEntity> findByUserIdAndDeviceFingerprint(UUID userId, String deviceFingerprint);

    List<MfaTrustedDeviceEntity> findByUserIdAndIsTrustedTrueAndRevokedAtIsNull(UUID userId);

    @Query("SELECT d FROM MfaTrustedDeviceEntity d WHERE d.userId = :userId AND d.isTrusted = true AND d.revokedAt IS NULL AND (d.expiresAt IS NULL OR d.expiresAt > :now)")
    List<MfaTrustedDeviceEntity> findActiveTrustedDevices(@Param("userId") UUID userId, @Param("now") OffsetDateTime now);

    @Query("SELECT COUNT(d) FROM MfaTrustedDeviceEntity d WHERE d.userId = :userId AND d.isTrusted = true AND d.revokedAt IS NULL")
    long countActiveTrustedDevices(@Param("userId") UUID userId);

    @Modifying
    @Query("UPDATE MfaTrustedDeviceEntity d SET d.lastSeenAt = :now WHERE d.id = :deviceId")
    void updateLastSeen(@Param("deviceId") UUID deviceId, @Param("now") OffsetDateTime now);

    @Modifying
    @Query("UPDATE MfaTrustedDeviceEntity d SET d.revokedAt = :now, d.revokedBy = :revokedBy, d.isTrusted = false WHERE d.id = :deviceId")
    void revokeDevice(@Param("deviceId") UUID deviceId, @Param("now") OffsetDateTime now, @Param("revokedBy") UUID revokedBy);

    @Query("SELECT d FROM MfaTrustedDeviceEntity d WHERE d.expiresAt IS NOT NULL AND d.expiresAt < :now AND d.isTrusted = true")
    List<MfaTrustedDeviceEntity> findExpiredDevices(@Param("now") OffsetDateTime now);

    @Modifying
    @Query("UPDATE MfaTrustedDeviceEntity d SET d.isTrusted = false WHERE d.expiresAt IS NOT NULL AND d.expiresAt < :now")
    int markExpiredDevicesAsUntrusted(@Param("now") OffsetDateTime now);

    List<MfaTrustedDeviceEntity> findByDeviceFingerprintAndTenantId(String deviceFingerprint, UUID tenantId);
}