package com.payshield.frauddetector.infrastructure.adapters;

import com.payshield.frauddetector.domain.Invoice;
import com.payshield.frauddetector.domain.ports.InvoiceRepository;
import com.payshield.frauddetector.infrastructure.jpa.InvoiceEntity;
import com.payshield.frauddetector.infrastructure.jpa.SpringInvoiceRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Component
public class JpaInvoiceRepositoryAdapter implements InvoiceRepository {

    private static final Logger log = LoggerFactory.getLogger(JpaInvoiceRepositoryAdapter.class);
    private final SpringInvoiceRepository invoices;

    // TEMPORARY: Remove encryption dependency to get app running
    public JpaInvoiceRepositoryAdapter(SpringInvoiceRepository invoices) {
        this.invoices = invoices;
        log.info("Invoice repository initialized (encryption temporarily disabled)");
    }

    @Override
    public Invoice save(Invoice invoice) {
        log.debug("Saving invoice: {}", invoice.getId());
        
        InvoiceEntity e = new InvoiceEntity();
        e.setId(invoice.getId());
        e.setTenantId(invoice.getTenantId());
        e.setVendorId(invoice.getVendorId());
        e.setAmount(invoice.getAmount());
        e.setCurrency(invoice.getCurrency());
        e.setReceivedAt(invoice.getReceivedAt());
        
        // TEMPORARY: Store as plaintext until encryption is properly configured
        e.setBankIban(invoice.getBankIban());
        e.setBankSwift(invoice.getBankSwift());
        e.setBankLast4(invoice.getBankLast4());
        
        e.setSourceMessageId(invoice.getSourceMessageId());
        e.setFileSha256(invoice.getFileSha256());

        try {
            invoices.save(e);
            log.debug("Invoice saved successfully: {}", invoice.getId());
            return invoice;
        } catch (Exception ex) {
            log.error("Failed to save invoice {}: {}", invoice.getId(), ex.getMessage());
            throw new RuntimeException("Failed to save invoice", ex);
        }
    }

    @Override
    public Optional<Invoice> findById(UUID tenantId, UUID invoiceId) {
        return invoices.findByTenantIdAndId(tenantId, invoiceId)
                .map(this::entityToDomain);
    }

    @Override
    public boolean existsByFileSha256(UUID tenantId, String sha256) {
        return invoices.existsByTenantIdAndFileSha256(tenantId, sha256);
    }

    @Override
    public Optional<Invoice> findByFileSha256(UUID tenantId, String sha256) {
        return invoices.findByTenantIdAndFileSha256(tenantId, sha256)
                .map(this::entityToDomain);
    }

    @Override
    public List<Invoice> listByTenant(UUID tenantId, int page, int size) {
        return invoices.findByTenantId(tenantId, PageRequest.of(page, size))
                .stream()
                .map(this::entityToDomain)
                .toList();
    }

    private Invoice entityToDomain(InvoiceEntity e) {
        return new Invoice(
                e.getId(), 
                e.getTenantId(), 
                e.getVendorId(), 
                e.getReceivedAt(), 
                e.getAmount(), 
                e.getCurrency(),
                e.getBankIban(),    // Plaintext for now
                e.getBankSwift(),   // Plaintext for now
                e.getBankLast4(), 
                e.getSourceMessageId(), 
                e.getFileSha256()
        );
    }
}
