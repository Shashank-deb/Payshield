package com.payshield.frauddetector.infrastructure.jpa;

import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface SpringInvoiceRepository extends JpaRepository<InvoiceEntity, UUID> {

    Boolean existsByTenantIdAndFileSha256(UUID tenantId, String sha256);

    // ➕ Add this line so adapter can resolve it
    Optional<InvoiceEntity> findByTenantIdAndFileSha256(UUID tenantId, String sha256);

    Optional<InvoiceEntity> findByTenantIdAndId(UUID tenantId, UUID id);

    List<InvoiceEntity> findByTenantId(UUID tenantId, Pageable pageable);
}
