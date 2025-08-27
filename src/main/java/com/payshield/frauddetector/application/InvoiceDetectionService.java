package com.payshield.frauddetector.application;

import com.payshield.frauddetector.domain.*;
import com.payshield.frauddetector.domain.ports.*;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.math.BigDecimal;
import java.nio.file.Path;
import java.time.OffsetDateTime;
import java.util.*;

@Service
public class InvoiceDetectionService {

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
        Optional<Invoice> existing = invoiceRepo.findByFileSha256(cmd.tenantId, fileSha256);
        if (existing.isPresent()) {
            return new InvoiceDetectionResult(existing.get().getId(), true);
        }

        Path stored = storage.store(cmd.tenantId, fileSha256, cmd.originalFilename, cmd.body);
        Parsed parsed = parser.parse(stored);

        String vendorName = (cmd.vendorName != null && !cmd.vendorName.isBlank()) ? cmd.vendorName : parsed.vendorName;
        String currency   = (cmd.currency != null && !cmd.currency.isBlank()) ? cmd.currency : parsed.currency;
        BigDecimal amount = (cmd.statedAmount != null) ? cmd.statedAmount : parsed.amount;

        DetectionEngine.Result result = engine.evaluate(cmd.tenantId, vendorName, parsed.bankLast4, cmd.senderDomain, vendorRepo);

        UUID vendorId = vendorRepo.findByName(cmd.tenantId, vendorName)
                .orElseGet(() -> vendorRepo.save(new Vendor(UUID.randomUUID(), cmd.tenantId, vendorName,
                        cmd.senderDomain.orElse(null), parsed.bankLast4))).getId();

        Invoice invoice = new Invoice(UUID.randomUUID(), cmd.tenantId, vendorId, OffsetDateTime.now(), amount, currency,
                parsed.bankIban, parsed.bankSwift, parsed.bankLast4, null, fileSha256);
        invoiceRepo.save(invoice);

        if (result.flagged()) {
            CaseRecord c = new CaseRecord(UUID.randomUUID(), cmd.tenantId, invoice.getId(), CaseState.FLAGGED, OffsetDateTime.now());
            caseRepo.save(c);
            outbox.publish(cmd.tenantId, "invoice.flagged",
                    "{\"invoiceId\":\"" + invoice.getId() + "\",\"caseId\":\"" + c.getId() + "\"}");
            notifier.sendCaseFlagged(cmd.tenantId, c.getId(), Map.of(
                    "invoiceId", invoice.getId().toString(),
                    "vendorName", vendorName,
                    "rules", result.getViolations().toString(),
                    "amount", amount != null ? amount.toString() : null,
                    "currency", currency
            ));
        }

        return new InvoiceDetectionResult(invoice.getId(), false);
    }

    public record InvoiceDetectionResult(UUID id, boolean alreadyExists) {}
}
