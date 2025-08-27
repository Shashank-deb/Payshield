package com.payshield.frauddetector.infrastructure.adapters;

import com.payshield.frauddetector.domain.CaseRecord;
import com.payshield.frauddetector.domain.CaseState;
import com.payshield.frauddetector.domain.ports.CaseRepository;
import com.payshield.frauddetector.infrastructure.jpa.CaseWorkflowEntity;
import com.payshield.frauddetector.infrastructure.jpa.SpringCaseRepository;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;
import java.util.UUID;

@Component
public class JpaCaseRepositoryAdapter implements CaseRepository {
    private final SpringCaseRepository cases;

    public JpaCaseRepositoryAdapter(SpringCaseRepository cases) {
        this.cases = cases;
    }

    @Override
    public CaseRecord save(CaseRecord c) {
        CaseWorkflowEntity e = new CaseWorkflowEntity();
        e.setId(c.getId());
        e.setTenantId(c.getTenantId());
        e.setInvoiceId(c.getInvoiceId());
        e.setState(c.getState().name());
        e.setCreatedAt(c.getCreatedAt());
        cases.save(e);
        return c;
    }

    @Override
    public Optional<CaseRecord> findById(UUID tenantId, UUID caseId) {
        return cases.findByTenantIdAndId(tenantId, caseId)
                .map(c -> new CaseRecord(c.getId(), c.getTenantId(), c.getInvoiceId(), CaseState.valueOf(c.getState()), c.getCreatedAt()));
    }

    @Override
    @Transactional
    public void updateState(UUID tenantId, UUID caseId, CaseState newState) {
        CaseWorkflowEntity e = cases.findByTenantIdAndId(tenantId, caseId)
                .orElseThrow(() -> new RuntimeException("Case not found"));
        e.setState(newState.name());
        cases.save(e);
    }
}
