// ==============================================================================
// MFA Authentication Attempt Repository
// File: src/main/java/com/payshield/frauddetector/infrastructure/jpa/SpringMfaAuthAttemptRepository.java
// ==============================================================================

package com.payshield.frauddetector.infrastructure.jpa;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.OffsetDateTime;
import java.util.List;
import java.util.UUID;

public interface SpringMfaAuthAttemptRepository extends JpaRepository<MfaAuthAttemptEntity, UUID> {

    List<MfaAuthAttemptEntity> findByUserIdAndTenantIdOrderByAttemptedAtDesc(UUID userId, UUID tenantId);

    @Query("SELECT COUNT(a) FROM MfaAuthAttemptEntity a WHERE a.userId = :userId AND a.success = false AND a.attemptedAt > :since")
    long countFailedAttemptsSince(@Param("userId") UUID userId, @Param("since") OffsetDateTime since);

    @Query("SELECT a FROM MfaAuthAttemptEntity a WHERE a.ipAddress = :ip AND a.attemptedAt > :since ORDER BY a.attemptedAt DESC")
    List<MfaAuthAttemptEntity> findByIpAddressSince(@Param("ip") String ip, @Param("since") OffsetDateTime since);

    @Query("SELECT a FROM MfaAuthAttemptEntity a WHERE a.success = false AND a.attemptedAt > :since ORDER BY a.attemptedAt DESC")
    List<MfaAuthAttemptEntity> findFailedAttemptsSince(@Param("since") OffsetDateTime since);

    @Query("SELECT COUNT(a) FROM MfaAuthAttemptEntity a WHERE a.tenantId = :tenantId AND a.success = true AND a.attemptedAt > :since")
    long countSuccessfulAttemptsForTenant(@Param("tenantId") UUID tenantId, @Param("since") OffsetDateTime since);

    List<MfaAuthAttemptEntity> findByDeviceFingerprintOrderByAttemptedAtDesc(String deviceFingerprint);

    @Query("SELECT a FROM MfaAuthAttemptEntity a WHERE a.userId = :userId AND a.attemptedAt BETWEEN :start AND :end ORDER BY a.attemptedAt DESC")
    List<MfaAuthAttemptEntity> findByUserIdAndDateRange(@Param("userId") UUID userId, @Param("start") OffsetDateTime start, @Param("end") OffsetDateTime end);
}