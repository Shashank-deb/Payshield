package com.payshield.frauddetector.infrastructure.jpa;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;
import java.util.UUID;

public interface SpringCaseRepository extends JpaRepository<CaseWorkflowEntity, UUID> {
    Optional<CaseWorkflowEntity> findByTenantIdAndId(UUID tenantId, UUID id);
}
