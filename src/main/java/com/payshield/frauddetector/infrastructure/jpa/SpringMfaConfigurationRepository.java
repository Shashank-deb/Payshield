// ==============================================================================
// MFA Configuration Repository
// File: src/main/java/com/payshield/frauddetector/infrastructure/jpa/SpringMfaConfigurationRepository.java
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

public interface SpringMfaConfigurationRepository extends JpaRepository<MfaConfigurationEntity, UUID> {

    Optional<MfaConfigurationEntity> findByUserIdAndTenantId(UUID userId, UUID tenantId);

    List<MfaConfigurationEntity> findByTenantIdAndStatus(UUID tenantId, MfaConfigurationEntity.MfaStatusType status);

    List<MfaConfigurationEntity> findByTenantId(UUID tenantId);

    boolean existsByUserIdAndStatus(UUID userId, MfaConfigurationEntity.MfaStatusType status);

    @Query("SELECT COUNT(m) FROM MfaConfigurationEntity m WHERE m.tenantId = :tenantId AND m.status = 'ENABLED'")
    long countEnabledByTenant(@Param("tenantId") UUID tenantId);

    @Modifying
    @Query("UPDATE MfaConfigurationEntity m SET m.failedAttempts = :attempts, m.updatedAt = :now WHERE m.userId = :userId")
    void updateFailedAttempts(@Param("userId") UUID userId, @Param("attempts") int attempts, @Param("now") OffsetDateTime now);

    @Modifying
    @Query("UPDATE MfaConfigurationEntity m SET m.status = :status, m.lockedUntil = :lockedUntil, m.updatedAt = :now WHERE m.userId = :userId")
    void updateLockStatus(@Param("userId") UUID userId, @Param("status") MfaConfigurationEntity.MfaStatusType status,
                          @Param("lockedUntil") OffsetDateTime lockedUntil, @Param("now") OffsetDateTime now);

    @Modifying
    @Query("UPDATE MfaConfigurationEntity m SET m.lastUsedAt = :now, m.failedAttempts = 0, m.updatedAt = :now WHERE m.userId = :userId")
    void updateLastUsed(@Param("userId") UUID userId, @Param("now") OffsetDateTime now);

    @Query("SELECT m FROM MfaConfigurationEntity m WHERE m.status = 'LOCKED' AND m.lockedUntil < :now")
    List<MfaConfigurationEntity> findExpiredLocks(@Param("now") OffsetDateTime now);

    List<MfaConfigurationEntity> findBySecretHash(String secretHash);
}