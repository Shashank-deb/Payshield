package com.payshield.frauddetector.infrastructure.adapters;

import com.payshield.frauddetector.domain.Invoice;
import com.payshield.frauddetector.domain.ports.InvoiceRepository;
import com.payshield.frauddetector.infrastructure.jpa.InvoiceEntity;
import com.payshield.frauddetector.infrastructure.jpa.SpringInvoiceRepository;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Component
public class JpaInvoiceRepositoryAdapter implements InvoiceRepository {
    private final SpringInvoiceRepository invoices;

    public JpaInvoiceRepositoryAdapter(SpringInvoiceRepository invoices) {
        this.invoices = invoices;
    }

    @Override
    public Invoice save(Invoice invoice) {
        InvoiceEntity e = new InvoiceEntity();
        e.setId(invoice.getId());
        e.setTenantId(invoice.getTenantId());
        e.setVendorId(invoice.getVendorId());
        e.setAmount(invoice.getAmount());
        e.setCurrency(invoice.getCurrency());
        e.setReceivedAt(invoice.getReceivedAt());
        e.setBankIban(invoice.getBankIban());
        e.setBankSwift(invoice.getBankSwift());
        e.setBankLast4(invoice.getBankLast4());
        e.setSourceMessageId(invoice.getSourceMessageId());
        e.setFileSha256(invoice.getFileSha256());
        invoices.save(e);
        return invoice;
    }

    @Override
    public Optional<Invoice> findById(UUID tenantId, UUID invoiceId) {
        return invoices.findByTenantIdAndId(tenantId, invoiceId)
                .map(e -> new Invoice(
                        e.getId(), e.getTenantId(), e.getVendorId(), e.getReceivedAt(), e.getAmount(), e.getCurrency(),
                        e.getBankIban(), e.getBankSwift(), e.getBankLast4(), e.getSourceMessageId(), e.getFileSha256()
                ));
    }

    @Override
    public boolean existsByFileSha256(UUID tenantId, String sha256) {
        return invoices.existsByTenantIdAndFileSha256(tenantId, sha256);
    }

    @Override
    public Optional<Invoice> findByFileSha256(UUID tenantId, String sha256) {
        return invoices.findByTenantIdAndFileSha256(tenantId, sha256)
                .map(e -> new Invoice(
                        e.getId(), e.getTenantId(), e.getVendorId(), e.getReceivedAt(), e.getAmount(), e.getCurrency(),
                        e.getBankIban(), e.getBankSwift(), e.getBankLast4(), e.getSourceMessageId(), e.getFileSha256()
                ));
    }

    @Override
    public List<Invoice> listByTenant(UUID tenantId, int page, int size) {
        return invoices.findByTenantId(tenantId, PageRequest.of(page, size))
                .stream()
                .map(e -> new Invoice(
                        e.getId(), e.getTenantId(), e.getVendorId(), e.getReceivedAt(), e.getAmount(), e.getCurrency(),
                        e.getBankIban(), e.getBankSwift(), e.getBankLast4(), e.getSourceMessageId(), e.getFileSha256()
                ))
                .toList();
    }
}
