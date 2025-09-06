// ==============================================================================
// MFA Backup Code Repository
// File: src/main/java/com/payshield/frauddetector/infrastructure/jpa/SpringMfaBackupCodeRepository.java
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

public interface SpringMfaBackupCodeRepository extends JpaRepository<MfaBackupCodeEntity, UUID> {

    List<MfaBackupCodeEntity> findByUserIdAndTenantId(UUID userId, UUID tenantId);

    List<MfaBackupCodeEntity> findByUserIdAndIsUsedFalse(UUID userId);

    Optional<MfaBackupCodeEntity> findByCodeHashAndIsUsedFalse(String codeHash);

    @Query("SELECT COUNT(b) FROM MfaBackupCodeEntity b WHERE b.userId = :userId AND b.isUsed = false")
    long countUnusedByUser(@Param("userId") UUID userId);

    @Modifying
    @Query("UPDATE MfaBackupCodeEntity b SET b.isUsed = true, b.usedAt = :usedAt, b.usedFromIp = :ip WHERE b.id = :codeId")
    void markAsUsed(@Param("codeId") UUID codeId, @Param("usedAt") OffsetDateTime usedAt, @Param("ip") String ip);

    @Modifying
    @Query("DELETE FROM MfaBackupCodeEntity b WHERE b.userId = :userId")
    void deleteAllByUserId(@Param("userId") UUID userId);

    @Query("SELECT b FROM MfaBackupCodeEntity b WHERE b.userId = :userId ORDER BY b.createdAt DESC")
    List<MfaBackupCodeEntity> findByUserIdOrderByCreatedAtDesc(@Param("userId") UUID userId);

    boolean existsByCodeHash(String codeHash);

    @Query("SELECT b FROM MfaBackupCodeEntity b WHERE b.userId = :userId AND b.isUsed = true ORDER BY b.usedAt DESC")
    List<MfaBackupCodeEntity> findUsedCodesByUser(@Param("userId") UUID userId);
}