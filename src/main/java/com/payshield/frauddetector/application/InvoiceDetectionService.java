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

    // Use enhanced detection engine
    private final DetectionEngine engine = new DetectionEngine();

    public interface PdfParser {
        Parsed parse(Path storedPath);
    }

    public static class Parsed {
        public String vendorName;
        public BigDecimal amount;
        public String currency;
        public String bankIban;
        public String bankSwift;
        public String bankLast4;
    }

    public interface OutboxPort {
        void publish(UUID tenantId, String type, String jsonPayload);
    }

    public InvoiceDetectionService(InvoiceRepository invoiceRepo, VendorHistoryRepository vendorRepo,
                                   CaseRepository caseRepo, FileStoragePort storage, NotifierPort notifier,
                                   PdfParser parser, OutboxPort outbox) {
        this.invoiceRepo = invoiceRepo;
        this.vendorRepo = vendorRepo;
        this.caseRepo = caseRepo;
        this.storage = storage;
        this.notifier = notifier;
        this.parser = parser;
        this.outbox = outbox;
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

        log.info("Final values - vendor: {}, currency: {}, amount: {}, bankLast4: {}, fullIban: {}",
                vendorName, currency, amount, parsed.bankLast4,
                parsed.bankIban != null ? parsed.bankIban.substring(0, 4) + "****" : "null");

        // ENHANCED: Run fraud detection with full invoice data using the correct method signature
        log.info("Running ENHANCED fraud detection with full invoice context...");

        DetectionEngine.Result result = engine.evaluate(
                cmd.tenantId,           // tenantId
                vendorName,             // vendorName
                parsed.bankLast4,       // bankLast4
                parsed.bankIban,        // fullIban for checksum validation
                amount,                 // amount for pattern analysis
                currency,               // currency for analysis
                cmd.senderDomain,       // senderDomain
                OffsetDateTime.now(),   // submissionTime
                vendorRepo              // vendorRepo
        );

        // Get risk assessment
        DetectionEngine.RiskAssessment riskAssessment = engine.assessRisk(result);

        log.info("Enhanced fraud detection result: flagged={}, riskScore={}, riskLevel={}, violations={}",
                result.flagged(), riskAssessment.riskScore, riskAssessment.riskLevel, result.getViolations());

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
        Invoice invoice = new Invoice(UUID.randomUUID(), cmd.tenantId, vendorId, OffsetDateTime.now(),
                amount, currency, parsed.bankIban, parsed.bankSwift, parsed.bankLast4, null, fileSha256);
        invoiceRepo.save(invoice);
        log.info("Invoice saved with ID: {}", invoice.getId());

        // Handle fraud detection results with enhanced risk assessment
        if (result.flagged()) {
            log.warn("FRAUD DETECTED - Risk Level: {} (Score: {}) - Creating case for invoice: {}",
                    riskAssessment.riskLevel, riskAssessment.riskScore, invoice.getId());

            CaseRecord c = new CaseRecord(UUID.randomUUID(), cmd.tenantId, invoice.getId(),
                    CaseState.FLAGGED, OffsetDateTime.now());
            caseRepo.save(c);
            log.info("Case created with ID: {} for risk level: {}", c.getId(), riskAssessment.riskLevel);

            // Enhanced outbox event with risk assessment
            String eventPayload = createEnhancedEventPayload(invoice, c, riskAssessment, result);
            outbox.publish(cmd.tenantId, "invoice.flagged", eventPayload);
            log.info("Enhanced outbox event published for case: {}", c.getId());

            // Enhanced notification with risk details
            Map<String, Object> notificationPayload = createEnhancedNotificationPayload(
                    invoice, vendorName, amount, currency, riskAssessment, result);

            notifier.sendCaseFlagged(cmd.tenantId, c.getId(), notificationPayload);
            log.info("Enhanced fraud notification sent - Case: {}, Risk: {}, Score: {}",
                    c.getId(), riskAssessment.riskLevel, riskAssessment.riskScore);
        } else {
            log.info("Invoice approved - Risk score: {} below threshold (50)", riskAssessment.riskScore);
        }

        log.info("Invoice upload and detection completed - invoiceId: {}, riskScore: {}",
                invoice.getId(), riskAssessment.riskScore);
        return new InvoiceDetectionResult(invoice.getId(), false);
    }

    /**
     * Create enhanced event payload with risk assessment details
     */
    private String createEnhancedEventPayload(Invoice invoice, CaseRecord caseRecord,
                                              DetectionEngine.RiskAssessment riskAssessment,
                                              DetectionEngine.Result detectionResult) {
        return String.format("""
            {
                "eventId": "%s",
                "eventType": "invoice.flagged",
                "timestamp": "%s",
                "tenantId": "%s",
                "invoiceId": "%s", 
                "caseId": "%s",
                "riskAssessment": {
                    "score": %d,
                    "level": "%s",
                    "recommendation": "%s",
                    "violations": %s
                },
                "invoice": {
                    "amount": "%s",
                    "currency": "%s",
                    "vendorId": "%s"
                }
            }""",
                UUID.randomUUID(),
                OffsetDateTime.now(),
                invoice.getTenantId(),
                invoice.getId(),
                caseRecord.getId(),
                riskAssessment.riskScore,
                riskAssessment.riskLevel,
                riskAssessment.recommendation,
                detectionResult.getViolations(),
                invoice.getAmount(),
                invoice.getCurrency(),
                invoice.getVendorId()
        );
    }

    /**
     * Create enhanced notification payload for alerts
     */
    private Map<String, Object> createEnhancedNotificationPayload(Invoice invoice, String vendorName,
                                                                  BigDecimal amount, String currency,
                                                                  DetectionEngine.RiskAssessment riskAssessment,
                                                                  DetectionEngine.Result detectionResult) {
        Map<String, Object> payload = new HashMap<>();

        // Basic invoice info
        payload.put("invoiceId", invoice.getId().toString());
        payload.put("vendorName", vendorName != null ? vendorName : "unknown");
        payload.put("amount", amount != null ? amount.toString() : "unknown");
        payload.put("currency", currency != null ? currency : "unknown");

        // Enhanced risk information
        payload.put("riskScore", riskAssessment.riskScore);
        payload.put("riskLevel", riskAssessment.riskLevel);
        payload.put("recommendation", riskAssessment.recommendation);
        payload.put("violations", detectionResult.getViolations().toString());
        payload.put("flaggedRules", new ArrayList<>(detectionResult.getViolations()));

        // Additional context for alerts
        payload.put("submissionTime", OffsetDateTime.now().toString());
        payload.put("tenantId", invoice.getTenantId().toString());

        return payload;
    }

    public record InvoiceDetectionResult(UUID id, boolean alreadyExists) {}
}