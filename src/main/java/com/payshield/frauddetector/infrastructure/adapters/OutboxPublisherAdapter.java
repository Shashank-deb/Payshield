package com.payshield.frauddetector.infrastructure.adapters;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.payshield.frauddetector.application.InvoiceDetectionService;
import com.payshield.frauddetector.infrastructure.jpa.OutboxEventEntity;
import com.payshield.frauddetector.infrastructure.jpa.SpringOutboxRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.util.Map;
import java.util.UUID;

@Component
public class OutboxPublisherAdapter implements InvoiceDetectionService.OutboxPort {

    private static final Logger log = LoggerFactory.getLogger(OutboxPublisherAdapter.class);

    private final SpringOutboxRepository outbox;
    private final ObjectMapper objectMapper;

    public OutboxPublisherAdapter(SpringOutboxRepository outbox, ObjectMapper objectMapper) {
        this.outbox = outbox;
        this.objectMapper = objectMapper;
    }

    @Override
    public void publish(UUID tenantId, String type, String jsonPayload) {
        try {
            log.info("Publishing outbox event - Tenant: {}, Type: {}", tenantId, type);

            // Validate JSON payload before storing
            validateJsonPayload(jsonPayload);

            OutboxEventEntity event = new OutboxEventEntity(
                    UUID.randomUUID(),
                    tenantId,
                    type,
                    jsonPayload
            );

            OutboxEventEntity saved = outbox.save(event);

            log.info("Successfully published outbox event - ID: {}, Type: {}, Tenant: {}",
                    saved.getEventId(), type, tenantId);

        } catch (Exception e) {
            log.error("Failed to publish outbox event - Tenant: {}, Type: {}, Payload: {}, Error: {}",
                    tenantId, type, jsonPayload, e.getMessage(), e);

            // Re-throw to ensure the calling transaction fails if outbox publishing fails
            throw new RuntimeException("Failed to publish outbox event", e);
        }
    }

    // Convenience methods for common event types
    public void publishInvoiceFlagged(UUID tenantId, UUID invoiceId, UUID caseId, Map<String, Object> additionalData) {
        try {
            Map<String, Object> payload = Map.of(
                    "invoiceId", invoiceId.toString(),
                    "caseId", caseId.toString(),
                    "eventType", "invoice.flagged",
                    "timestamp", java.time.OffsetDateTime.now().toString(),
                    "additionalData", additionalData != null ? additionalData : Map.of()
            );

            String jsonPayload = objectMapper.writeValueAsString(payload);
            publish(tenantId, "invoice.flagged", jsonPayload);

        } catch (JsonProcessingException e) {
            throw new RuntimeException("Failed to serialize invoice.flagged payload", e);
        }
    }

    public void publishCaseApproved(UUID tenantId, UUID caseId, UUID invoiceId, String approvedBy) {
        try {
            Map<String, Object> payload = Map.of(
                    "caseId", caseId.toString(),
                    "invoiceId", invoiceId.toString(),
                    "approvedBy", approvedBy,
                    "eventType", "case.approved",
                    "timestamp", java.time.OffsetDateTime.now().toString()
            );

            String jsonPayload = objectMapper.writeValueAsString(payload);
            publish(tenantId, "case.approved", jsonPayload);

        } catch (JsonProcessingException e) {
            throw new RuntimeException("Failed to serialize case.approved payload", e);
        }
    }

    public void publishCaseRejected(UUID tenantId, UUID caseId, UUID invoiceId, String rejectedBy, String reason) {
        try {
            Map<String, Object> payload = Map.of(
                    "caseId", caseId.toString(),
                    "invoiceId", invoiceId.toString(),
                    "rejectedBy", rejectedBy,
                    "reason", reason != null ? reason : "No reason provided",
                    "eventType", "case.rejected",
                    "timestamp", java.time.OffsetDateTime.now().toString()
            );

            String jsonPayload = objectMapper.writeValueAsString(payload);
            publish(tenantId, "case.rejected", jsonPayload);

        } catch (JsonProcessingException e) {
            throw new RuntimeException("Failed to serialize case.rejected payload", e);
        }
    }

    private void validateJsonPayload(String jsonPayload) {
        if (jsonPayload == null || jsonPayload.trim().isEmpty()) {
            throw new IllegalArgumentException("JSON payload cannot be null or empty");
        }

        try {
            // Validate that it's proper JSON
            objectMapper.readTree(jsonPayload);
        } catch (JsonProcessingException e) {
            throw new IllegalArgumentException("Invalid JSON payload: " + e.getMessage(), e);
        }
    }
}