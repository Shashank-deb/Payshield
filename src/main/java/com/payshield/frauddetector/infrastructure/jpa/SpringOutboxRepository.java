package com.payshield.frauddetector.infrastructure.jpa;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.OffsetDateTime;
import java.util.List;
import java.util.UUID;

public interface SpringOutboxRepository extends JpaRepository<OutboxEventEntity, UUID> {

    // Main method for batch processing unprocessed events
    List<OutboxEventEntity> findTop50ByProcessedAtIsNullOrderByOccurredAtAsc();

    // Statistics methods
    long countByProcessedAtIsNull();
    long countByProcessedAtIsNotNull();

    // Find events by type
    List<OutboxEventEntity> findByTypeOrderByOccurredAtDesc(String type);

    // Find events by tenant
    List<OutboxEventEntity> findByTenantIdOrderByOccurredAtDesc(UUID tenantId);

    // Find recent events (for debugging/monitoring)
    @Query("SELECT e FROM OutboxEventEntity e WHERE e.occurredAt >= :since ORDER BY e.occurredAt DESC")
    List<OutboxEventEntity> findEventsSince(@Param("since") OffsetDateTime since);

    // Find failed events (occurred more than X time ago but not processed)
    @Query("SELECT e FROM OutboxEventEntity e WHERE e.processedAt IS NULL AND e.occurredAt < :threshold ORDER BY e.occurredAt ASC")
    List<OutboxEventEntity> findFailedEvents(@Param("threshold") OffsetDateTime threshold);

    // Clean up old processed events (for maintenance)
    void deleteByProcessedAtIsNotNullAndProcessedAtBefore(OffsetDateTime cutoff);
}