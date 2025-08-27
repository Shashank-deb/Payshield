package com.payshield.frauddetector.infrastructure.adapters;

import com.payshield.frauddetector.application.InvoiceDetectionService;
import com.payshield.frauddetector.infrastructure.jpa.OutboxEventEntity;
import com.payshield.frauddetector.infrastructure.jpa.SpringOutboxRepository;
import org.springframework.stereotype.Component;

import java.time.OffsetDateTime;
import java.util.UUID;

@Component
public class OutboxPublisherAdapter implements InvoiceDetectionService.OutboxPort {
    private final SpringOutboxRepository outbox;

    public OutboxPublisherAdapter(SpringOutboxRepository outbox) {
        this.outbox = outbox;
    }

    @Override
    public void publish(UUID tenantId, String type, String jsonPayload) {
        OutboxEventEntity e = new OutboxEventEntity();
        e.setEventId(UUID.randomUUID());
        e.setTenantId(tenantId);
        e.setType(type);
        e.setPayloadJson(jsonPayload);
        e.setOccurredAt(OffsetDateTime.now());
        outbox.save(e);
    }
}
