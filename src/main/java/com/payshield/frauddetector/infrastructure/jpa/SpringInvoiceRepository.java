package com.payshield.frauddetector.infrastructure.jpa;

import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface SpringInvoiceRepository extends JpaRepository<InvoiceEntity, UUID> {

    Boolean existsByTenantIdAndFileSha256(UUID tenantId, String sha256);

    Optional<InvoiceEntity> findByTenantIdAndFileSha256(UUID tenantId, String sha256);

    Optional<InvoiceEntity> findByTenantIdAndId(UUID tenantId, UUID id);

    List<InvoiceEntity> findByTenantId(UUID tenantId, Pageable pageable);

    // ➕ NEW: Find by IBAN hash for duplicate detection
    Optional<InvoiceEntity> findByTenantIdAndBankIbanHash(UUID tenantId, String ibanHash);

    // ➕ NEW: Check if IBAN hash exists for duplicate prevention
    Boolean existsByTenantIdAndBankIbanHash(UUID tenantId, String ibanHash);

    // ➕ NEW: Migration verification methods
    long countByBankIbanIsNotNull();
    long countByBankSwiftIsNotNull();

    // ➕ FIXED: Use proper query for encrypted fields count
    @Query("SELECT COUNT(i) FROM InvoiceEntity i WHERE i.bankIbanEncrypted IS NOT NULL OR i.bankSwiftEncrypted IS NOT NULL")
    long countByBankIbanEncryptedIsNotNullOrBankSwiftEncryptedIsNotNull();
}