package com.payshield.frauddetector.infrastructure.notify;

import com.payshield.frauddetector.domain.ports.NotifierPort;
import org.slf4j.Logger; import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.util.Map;
import java.util.UUID;

@Component
public class LoggingNotifier implements NotifierPort {
  private static final Logger log = LoggerFactory.getLogger(LoggingNotifier.class);
  @Override public void sendCaseFlagged(UUID tenantId, UUID caseId, Map<String, Object> payload) {
    log.warn("Tenant {} case {} FLAGGED: {}", tenantId, caseId, payload);
  }
}
