package com.payshield.frauddetector.infrastructure.jpa;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;
import java.util.UUID;

public interface SpringVendorRepository  extends JpaRepository<VendorEntity, UUID> {

    Optional<VendorEntity> findByTenantIdAndName(UUID tenantId, String name);
}
