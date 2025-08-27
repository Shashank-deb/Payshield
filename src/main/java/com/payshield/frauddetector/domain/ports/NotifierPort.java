package com.payshield.frauddetector.domain.ports;

import java.util.Map;
import java.util.UUID;

public interface NotifierPort {

    void sendCaseFlagged(UUID tenantId, UUID caseId, Map<String,Object> payload);
}
