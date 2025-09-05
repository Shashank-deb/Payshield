// ==============================================================================
// STEP 1B: Update ONLY the constructor and field injection
// File: src/main/java/com/payshield/frauddetector/infrastructure/adapters/JpaInvoiceRepositoryAdapter.java
// ==============================================================================

package com.payshield.frauddetector.infrastructure.adapters;

import com.payshield.frauddetector.domain.Invoice;
import com.payshield.frauddetector.domain.ports.InvoiceRepository;
import com.payshield.frauddetector.infrastructure.encryption.FieldEncryptionService; // ✅ ADD THIS IMPORT
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
    private final FieldEncryptionService encryptionService; // ✅ ADD THIS FIELD

    // ✅ UPDATE CONSTRUCTOR - Add FieldEncryptionService parameter
    public JpaInvoiceRepositoryAdapter(SpringInvoiceRepository invoices,
                                       FieldEncryptionService encryptionService) {
        this.invoices = invoices;
        this.encryptionService = encryptionService; // ✅ ADD THIS LINE
        log.info("Invoice repository initialized with encryption service");
    }

    // 🔄 KEEP ALL OTHER METHODS UNCHANGED FOR NOW
    @Override
    public Invoice save(Invoice invoice) {
        log.debug("Saving invoice with encryption: {}", invoice.getId());

        InvoiceEntity e = new InvoiceEntity();
        e.setId(invoice.getId());
        e.setTenantId(invoice.getTenantId());
        e.setVendorId(invoice.getVendorId());
        e.setAmount(invoice.getAmount());
        e.setCurrency(invoice.getCurrency());
        e.setReceivedAt(invoice.getReceivedAt());

        // ✅ NEW: Encrypt sensitive banking data
        try {
            if (invoice.getBankIban() != null && !invoice.getBankIban().isBlank()) {
                log.debug("Encrypting IBAN for invoice: {}", invoice.getId());
                e.setBankIbanEncrypted(encryptionService.encrypt(invoice.getBankIban()));
                e.setBankIbanHash(encryptionService.generateHash(invoice.getBankIban()));
                // Clear the plaintext field (for new records)
                e.setBankIban(null);
            }

            if (invoice.getBankSwift() != null && !invoice.getBankSwift().isBlank()) {
                log.debug("Encrypting SWIFT for invoice: {}", invoice.getId());
                e.setBankSwiftEncrypted(encryptionService.encrypt(invoice.getBankSwift()));
                // Clear the plaintext field (for new records)
                e.setBankSwift(null);
            }

            // Bank last 4 can remain plaintext for searching/display
            e.setBankLast4(invoice.getBankLast4());

            log.info("✅ Successfully encrypted sensitive data for invoice: {}", invoice.getId());

        } catch (Exception encryptionEx) {
            log.error("❌ Encryption failed for invoice {}: {}", invoice.getId(), encryptionEx.getMessage());
            throw new RuntimeException("Failed to encrypt sensitive data", encryptionEx);
        }

        e.setSourceMessageId(invoice.getSourceMessageId());
        e.setFileSha256(invoice.getFileSha256());

        try {
            invoices.save(e);
            log.debug("Invoice saved successfully with encrypted data: {}", invoice.getId());
            return invoice;
        } catch (Exception ex) {
            log.error("Failed to save invoice {}: {}", invoice.getId(), ex.getMessage());
            throw new RuntimeException("Failed to save invoice", ex);
        }
    }

    // 🔄 KEEP ALL OTHER METHODS EXACTLY THE SAME
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
        log.debug("Converting entity to domain with decryption for invoice: {}", e.getId());

        String bankIban = null;
        String bankSwift = null;

        try {
            // ✅ NEW: Try encrypted fields first, fallback to legacy plaintext
            if (e.getBankIbanEncrypted() != null && !e.getBankIbanEncrypted().isBlank()) {
                log.debug("Decrypting IBAN for invoice: {}", e.getId());
                bankIban = encryptionService.decrypt(e.getBankIbanEncrypted());
            } else if (e.getBankIban() != null && !e.getBankIban().isBlank()) {
                log.debug("Using legacy plaintext IBAN for invoice: {}", e.getId());
                bankIban = e.getBankIban(); // Legacy plaintext fallback
            }

            if (e.getBankSwiftEncrypted() != null && !e.getBankSwiftEncrypted().isBlank()) {
                log.debug("Decrypting SWIFT for invoice: {}", e.getId());
                bankSwift = encryptionService.decrypt(e.getBankSwiftEncrypted());
            } else if (e.getBankSwift() != null && !e.getBankSwift().isBlank()) {
                log.debug("Using legacy plaintext SWIFT for invoice: {}", e.getId());
                bankSwift = e.getBankSwift(); // Legacy plaintext fallback
            }

            if (bankIban != null || bankSwift != null) {
                log.debug("✅ Successfully decrypted banking data for invoice: {}", e.getId());
            }

        } catch (Exception decryptionEx) {
            log.error("❌ Decryption failed for invoice {}: {}", e.getId(), decryptionEx.getMessage());
            // Don't fail the entire operation - return null for banking fields
            log.warn("Continuing with null banking data due to decryption failure");
            bankIban = null;
            bankSwift = null;
        }

        return new Invoice(
                e.getId(),
                e.getTenantId(),
                e.getVendorId(),
                e.getReceivedAt(),
                e.getAmount(),
                e.getCurrency(),
                bankIban,           // ✅ Decrypted IBAN
                bankSwift,          // ✅ Decrypted SWIFT
                e.getBankLast4(),   // Plaintext (safe to display)
                e.getSourceMessageId(),
                e.getFileSha256()
        );
    }
}