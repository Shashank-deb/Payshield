package com.payshield.frauddetector.infrastructure.jpa;

import jakarta.persistence.*;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;
import java.time.OffsetDateTime;
import java.util.UUID;

@Entity
@Table(name = "outbox")
public class OutboxEventEntity {
    @Id
    @Column(name = "event_id")
    private UUID eventId;

    @Column(name = "tenant_id", nullable = false)
    private UUID tenantId;

    @Column(nullable = false)
    private String type;

    @Column(name = "payload_json", nullable = false)
    @JdbcTypeCode(SqlTypes.JSON)
    private String payloadJson;

    @Column(name = "occurred_at", nullable = false)
    private OffsetDateTime occurredAt;

    @Column(name = "processed_at")
    private OffsetDateTime processedAt;

    // Constructors
    public OutboxEventEntity() {}

    public OutboxEventEntity(UUID eventId, UUID tenantId, String type, String payloadJson) {
        this.eventId = eventId;
        this.tenantId = tenantId;
        this.type = type;
        this.payloadJson = payloadJson;
        this.occurredAt = OffsetDateTime.now();
    }

    // Getters and Setters
    public UUID getEventId() { return eventId; }
    public void setEventId(UUID eventId) { this.eventId = eventId; }

    public UUID getTenantId() { return tenantId; }
    public void setTenantId(UUID tenantId) { this.tenantId = tenantId; }

    public String getType() { return type; }
    public void setType(String type) { this.type = type; }

    public String getPayloadJson() { return payloadJson; }
    public void setPayloadJson(String payloadJson) { this.payloadJson = payloadJson; }

    public OffsetDateTime getOccurredAt() { return occurredAt; }
    public void setOccurredAt(OffsetDateTime occurredAt) { this.occurredAt = occurredAt; }

    public OffsetDateTime getProcessedAt() { return processedAt; }
    public void setProcessedAt(OffsetDateTime processedAt) { this.processedAt = processedAt; }

    // Helper methods for easier usage
    public boolean isProcessed() {
        return processedAt != null;
    }

    public void markAsProcessed() {
        this.processedAt = OffsetDateTime.now();
    }

    @Override
    public String toString() {
        return "OutboxEventEntity{" +
                "eventId=" + eventId +
                ", tenantId=" + tenantId +
                ", type='" + type + '\'' +
                ", occurredAt=" + occurredAt +
                ", processedAt=" + processedAt +
                '}';
    }
}