package com.payshield.frauddetector.infrastructure.outbox;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.payshield.frauddetector.infrastructure.jpa.OutboxEventEntity;
import com.payshield.frauddetector.infrastructure.jpa.SpringOutboxRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.time.OffsetDateTime;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@Component
public class OutboxDispatcher {
  private static final Logger log = LoggerFactory.getLogger(OutboxDispatcher.class);

  private final SpringOutboxRepository repo;
  private final ObjectMapper objectMapper;
  private final boolean enableDispatch;
  private final int batchSize;

  public OutboxDispatcher(
          SpringOutboxRepository repo,
          ObjectMapper objectMapper,
          @Value("${app.outbox.enabled:true}") boolean enableDispatch,
          @Value("${app.outbox.batch-size:50}") int batchSize) {
    this.repo = repo;
    this.objectMapper = objectMapper;
    this.enableDispatch = enableDispatch;
    this.batchSize = batchSize;

    log.info("OutboxDispatcher initialized - enabled: {}, batchSize: {}", enableDispatch, batchSize);
  }

  @Scheduled(fixedDelayString = "${app.outbox.poll-ms:5000}")
  @Transactional
  public void dispatch() {
    if (!enableDispatch) {
      log.debug("Outbox dispatch is disabled");
      return;
    }

    try {
      List<OutboxEventEntity> batch = repo.findTop50ByProcessedAtIsNullOrderByOccurredAtAsc();

      if (batch.isEmpty()) {
        log.trace("No outbox events to process");
        return;
      }

      log.info("Processing {} outbox events", batch.size());

      for (OutboxEventEntity event : batch) {
        try {
          processEvent(event);
          event.markAsProcessed();
          repo.save(event);

          log.debug("Successfully processed outbox event: {}", event.getEventId());

        } catch (Exception e) {
          log.error("Failed to process outbox event {}: {}",
                  event.getEventId(), e.getMessage(), e);

          // TODO: Implement retry logic or dead letter queue
          // For now, we'll leave the event unprocessed and try again later
        }
      }

    } catch (Exception e) {
      log.error("Error during outbox dispatch batch processing: {}", e.getMessage(), e);
    }
  }

  private void processEvent(OutboxEventEntity event) throws Exception {
    log.info("Processing outbox event - ID: {}, Type: {}, Tenant: {}",
            event.getEventId(), event.getType(), event.getTenantId());

    // Parse the JSON payload for validation
    Map<String, Object> payload = objectMapper.readValue(event.getPayloadJson(), Map.class);

    switch (event.getType()) {
      case "invoice.flagged" -> processInvoiceFlagged(event, payload);
      case "case.approved" -> processCaseApproved(event, payload);
      case "case.rejected" -> processCaseRejected(event, payload);
      default -> {
        log.warn("Unknown event type: {} for event {}", event.getType(), event.getEventId());
        // Mark as processed to avoid infinite retries for unknown types
      }
    }
  }

  private void processInvoiceFlagged(OutboxEventEntity event, Map<String, Object> payload) {
    log.info("Processing invoice.flagged event: {}", event.getEventId());

    // Extract key information
    String invoiceId = (String) payload.get("invoiceId");
    String caseId = (String) payload.get("caseId");

    // TODO: Integrate with actual notification systems
    // Examples:
    // - Send Slack notification to fraud-alerts channel
    // - Send email to compliance team
    // - Create Jira ticket for manual review
    // - Webhook to external fraud management system

    log.warn("🚨 FRAUD ALERT - Tenant: {}, Invoice: {}, Case: {}",
            event.getTenantId(), invoiceId, caseId);

    // Simulate notification success
    simulateNotificationDelivery("invoice.flagged", event.getTenantId().toString(), payload);
  }

  private void processCaseApproved(OutboxEventEntity event, Map<String, Object> payload) {
    log.info("Processing case.approved event: {}", event.getEventId());

    // TODO: Integration points for approved cases:
    // - Update external accounting system
    // - Release payment holds
    // - Notify requestor of approval

    simulateNotificationDelivery("case.approved", event.getTenantId().toString(), payload);
  }

  private void processCaseRejected(OutboxEventEntity event, Map<String, Object> payload) {
    log.info("Processing case.rejected event: {}", event.getEventId());

    // TODO: Integration points for rejected cases:
    // - Block vendor in payment system
    // - Escalate to security team
    // - Update risk scoring models

    simulateNotificationDelivery("case.rejected", event.getTenantId().toString(), payload);
  }

  private void simulateNotificationDelivery(String eventType, String tenantId, Map<String, Object> payload) {
    // This simulates successful delivery to external systems
    // Replace with actual implementation for:
    // - Slack webhooks
    // - Email service (SendGrid, SES, etc.)
    // - SMS notifications
    // - Push notifications
    // - External API calls

    log.info("📤 Notification delivered - Type: {}, Tenant: {}, Payload: {}",
            eventType, tenantId, payload);
  }

  // Manual processing method for testing/debugging
  public void processEventById(UUID eventId) {
    OutboxEventEntity event = repo.findById(eventId)
            .orElseThrow(() -> new IllegalArgumentException("Event not found: " + eventId));

    if (event.isProcessed()) {
      log.warn("Event {} is already processed", eventId);
      return;
    }

    try {
      processEvent(event);
      event.markAsProcessed();
      repo.save(event);
      log.info("Manually processed event: {}", eventId);
    } catch (Exception e) {
      log.error("Failed to manually process event {}: {}", eventId, e.getMessage(), e);
      throw new RuntimeException("Manual processing failed", e);
    }
  }

  // Statistics for monitoring
  public OutboxStats getStats() {
    long pending = repo.countByProcessedAtIsNull();
    long processed = repo.countByProcessedAtIsNotNull();

    return new OutboxStats(pending, processed, enableDispatch);
  }

  public record OutboxStats(long pendingEvents, long processedEvents, boolean dispatchEnabled) {}
}