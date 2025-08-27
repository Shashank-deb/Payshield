package com.payshield.frauddetector.domain.ports;

import com.payshield.frauddetector.domain.Invoice;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface InvoiceRepository {
    Invoice save(Invoice invoice);

    Optional<Invoice> findById(UUID tenantId, UUID invoiceId);

    boolean existsByFileSha256(UUID tenantId, String sha256);

    // ➕ Add this line
    Optional<Invoice> findByFileSha256(UUID tenantId, String sha256);

    List<Invoice> listByTenant(UUID tenantId, int page, int size);
}
