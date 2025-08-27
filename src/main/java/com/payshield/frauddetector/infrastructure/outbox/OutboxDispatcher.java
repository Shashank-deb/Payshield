package com.payshield.frauddetector.infrastructure.outbox;

import com.payshield.frauddetector.infrastructure.jpa.OutboxEventEntity;
import com.payshield.frauddetector.infrastructure.jpa.SpringOutboxRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.time.OffsetDateTime;
import java.util.List;

@Component
public class OutboxDispatcher {
  private static final Logger log = LoggerFactory.getLogger(OutboxDispatcher.class);
  private final SpringOutboxRepository repo;
  public OutboxDispatcher(SpringOutboxRepository repo){ this.repo = repo; }

  @Scheduled(fixedDelayString="${app.outbox.poll-ms:3000}")
  @Transactional
  public void dispatch(){
    List<OutboxEventEntity> batch = repo.findTop50ByProcessedAtIsNullOrderByOccurredAtAsc();
    for (OutboxEventEntity e : batch){
      // TODO: integrate Slack/Email/Webhook. On success:
      log.info("Publishing outbox event {} type={} tenant={}", e.getEventId(), e.getType(), e.getTenantId());
      e.setProcessedAt(OffsetDateTime.now());
      repo.save(e);
    }
  }
}
