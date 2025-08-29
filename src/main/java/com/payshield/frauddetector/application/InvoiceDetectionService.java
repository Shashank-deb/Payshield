package com.payshield.frauddetector.application;

import com.payshield.frauddetector.domain.*;
import com.payshield.frauddetector.domain.ports.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.math.BigDecimal;
import java.nio.file.Path;
import java.time.OffsetDateTime;
import java.util.*;

@Service
public class InvoiceDetectionService {

    private static final Logger log = LoggerFactory.getLogger(InvoiceDetectionService.class);

    private final InvoiceRepository invoiceRepo;
    private final VendorHistoryRepository vendorRepo;
    private final CaseRepository caseRepo;
    private final FileStoragePort storage;
    private final NotifierPort notifier;
    private final PdfParser parser;
    private final OutboxPort outbox;
    private final DetectionEngine engine = new DetectionEngine();

    public interface PdfParser { Parsed parse(Path storedPath); }
    public static class Parsed {
        public String vendorName; public BigDecimal amount; public String currency;
        public String bankIban; public String bankSwift; public String bankLast4;
    }
    public interface OutboxPort { void publish(UUID tenantId, String type, String jsonPayload); }

    public InvoiceDetectionService(InvoiceRepository invoiceRepo, VendorHistoryRepository vendorRepo, CaseRepository caseRepo,
                                   FileStoragePort storage, NotifierPort notifier, PdfParser parser, OutboxPort outbox) {
        this.invoiceRepo = invoiceRepo; this.vendorRepo = vendorRepo; this.caseRepo = caseRepo;
        this.storage = storage; this.notifier = notifier; this.parser = parser; this.outbox = outbox;
    }

    @Transactional
    public InvoiceDetectionResult uploadAndDetect(UploadInvoiceCommand cmd, String fileSha256) {
        log.info("Starting invoice upload and detection - vendor: {}, tenantId: {}, fileSha256: {}",
                cmd.vendorName, cmd.tenantId, fileSha256);

        // Check for duplicate
        Optional<Invoice> existing = invoiceRepo.findByFileSha256(cmd.tenantId, fileSha256);
        if (existing.isPresent()) {
            log.info("Invoice already exists with same file hash: {}", existing.get().getId());
            return new InvoiceDetectionResult(existing.get().getId(), true);
        }

        // Store file
        log.info("Storing file with original name: {}", cmd.originalFilename);
        Path stored = storage.store(cmd.tenantId, fileSha256, cmd.originalFilename, cmd.body);

        // Parse PDF
        log.info("Parsing PDF file: {}", stored);
        Parsed parsed = parser.parse(stored);
        log.info("PDF parsing result - vendor: {}, amount: {}, currency: {}, bankLast4: {}, bankIban: {}, bankSwift: {}",
                parsed.vendorName, parsed.amount, parsed.currency, parsed.bankLast4, parsed.bankIban, parsed.bankSwift);

        // Determine final values (command overrides PDF)
        String vendorName = (cmd.vendorName != null && !cmd.vendorName.isBlank()) ? cmd.vendorName : parsed.vendorName;
        String currency   = (cmd.currency != null && !cmd.currency.isBlank()) ? cmd.currency : parsed.currency;
        BigDecimal amount = (cmd.statedAmount != null) ? cmd.statedAmount : parsed.amount;

        log.info("Final values - vendor: {}, currency: {}, amount: {}, bankLast4: {}",
                vendorName, currency, amount, parsed.bankLast4);

        // Run fraud detection
        log.info("Running fraud detection for vendor: {}, bankLast4: {}, senderDomain: {}",
                vendorName, parsed.bankLast4, cmd.senderDomain.orElse("none"));

        DetectionEngine.Result result = engine.evaluate(cmd.tenantId, vendorName, parsed.bankLast4, cmd.senderDomain, vendorRepo);
        log.info("Fraud detection result: flagged={}, violations={}", result.flagged(), result.getViolations());

        // Create or get vendor
        UUID vendorId = vendorRepo.findByName(cmd.tenantId, vendorName)
                .orElseGet(() -> {
                    log.info("Creating new vendor: {}", vendorName);
                    Vendor newVendor = new Vendor(UUID.randomUUID(), cmd.tenantId, vendorName,
                            cmd.senderDomain.orElse(null), parsed.bankLast4);
                    return vendorRepo.save(newVendor);
                }).getId();

        // Save invoice
        log.info("Saving invoice with vendorId: {}", vendorId);
        Invoice invoice = new Invoice(UUID.randomUUID(), cmd.tenantId, vendorId, OffsetDateTime.now(), amount, currency,
                parsed.bankIban, parsed.bankSwift, parsed.bankLast4, null, fileSha256);
        invoiceRepo.save(invoice);
        log.info("Invoice saved with ID: {}", invoice.getId());

        // Handle fraud detection results
        if (result.flagged()) {
            log.info("Creating case for flagged invoice: {}", invoice.getId());
            CaseRecord c = new CaseRecord(UUID.randomUUID(), cmd.tenantId, invoice.getId(), CaseState.FLAGGED, OffsetDateTime.now());
            caseRepo.save(c);
            log.info("Case created with ID: {}", c.getId());

            // Publish outbox event
            String eventPayload = "{\"invoiceId\":\"" + invoice.getId() + "\",\"caseId\":\"" + c.getId() + "\"}";
            outbox.publish(cmd.tenantId, "invoice.flagged", eventPayload);
            log.info("Outbox event published for case: {}", c.getId());

            // Send notification - use HashMap to allow null values
            Map<String, Object> notificationPayload = new HashMap<>();
            notificationPayload.put("invoiceId", invoice.getId().toString());
            notificationPayload.put("vendorName", vendorName != null ? vendorName : "unknown");
            notificationPayload.put("rules", result.getViolations().toString());
            notificationPayload.put("amount", amount != null ? amount.toString() : "unknown");
            notificationPayload.put("currency", currency != null ? currency : "unknown");

            notifier.sendCaseFlagged(cmd.tenantId, c.getId(), notificationPayload);
            log.info("Notification sent for flagged case: {}", c.getId());
        } else {
            log.info("Invoice not flagged, no case created");
        }

        log.info("Invoice upload and detection completed - invoiceId: {}", invoice.getId());
        return new InvoiceDetectionResult(invoice.getId(), false);
    }

    public record InvoiceDetectionResult(UUID id, boolean alreadyExists) {}
}