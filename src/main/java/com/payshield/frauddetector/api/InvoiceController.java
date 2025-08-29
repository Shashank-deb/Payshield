package com.payshield.frauddetector.api;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.payshield.frauddetector.api.dto.UploadInvoiceRequest;
import com.payshield.frauddetector.application.InvoiceDetectionService;
import com.payshield.frauddetector.application.UploadInvoiceCommand;
import com.payshield.frauddetector.config.TenantContext;
import com.payshield.frauddetector.domain.ports.InvoiceRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

@RestController
@RequestMapping("/invoices")
public class InvoiceController {

    private static final Logger log = LoggerFactory.getLogger(InvoiceController.class);
    private final InvoiceDetectionService service;
    private final InvoiceRepository invoices;
    private final ObjectMapper mapper = new ObjectMapper();

    public InvoiceController(InvoiceDetectionService service, InvoiceRepository invoices) {
        this.service = service; this.invoices = invoices;
    }

    @PostMapping(value = "/upload", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<?> upload(@RequestPart("file") MultipartFile file,
                                    @RequestPart(value="meta", required=false) String metaJson,
                                    @RequestHeader(value="Idempotency-Key", required=false) String idempotencyKey,
                                    @RequestHeader(value="X-Sender-Domain", required=false) String senderDomain) throws IOException {

        log.info("Invoice upload request - filename: {}, contentType: {}, size: {}",
                file.getOriginalFilename(), file.getContentType(), file.getSize());

        UUID tenantId = TenantContext.getTenantId();
        if (tenantId == null) {
            log.error("No tenant ID in context");
            return ResponseEntity.badRequest().body(Map.of("error", "Missing X-Tenant-Id header"));
        }

        // Parse meta JSON if provided
        UploadInvoiceRequest meta = null;
        if (metaJson != null && !metaJson.isBlank()) {
            try {
                meta = mapper.readValue(metaJson, UploadInvoiceRequest.class);
                log.info("Parsed meta: vendorName={}, currency={}", meta.vendorName, meta.currency);
            } catch (Exception e) {
                log.error("Failed to parse meta JSON: {}", metaJson, e);
                return ResponseEntity.badRequest().body(Map.of("error", "Invalid meta JSON: " + e.getMessage()));
            }
        }

        log.info("Processing upload for tenant: {}, vendor: {}", tenantId, meta != null ? meta.vendorName : "null");

        // Validate file
        if (file.isEmpty()) {
            log.error("Empty file uploaded");
            return ResponseEntity.badRequest().body(Map.of("error", "File is empty"));
        }

        String sha256 = sha256Hex(file.getBytes());
        log.info("File SHA256: {}", sha256);

        UploadInvoiceCommand cmd = new UploadInvoiceCommand(
                tenantId,
                meta != null ? meta.vendorName : null,
                Optional.ofNullable(senderDomain),
                null,
                meta != null ? meta.currency : null,
                file.getOriginalFilename() != null ? file.getOriginalFilename() : "upload.pdf",
                idempotencyKey != null ? idempotencyKey : sha256,
                file.getInputStream()
        );

        log.info("Calling fraud detection service with vendor: {}", cmd.vendorName);
        var result = service.uploadAndDetect(cmd, sha256);
        log.info("Fraud detection completed - invoiceId: {}, alreadyExists: {}", result.id(), result.alreadyExists());

        return ResponseEntity.ok(Map.of(
                "status", result.alreadyExists() ? "already_exists" : "created",
                "id", result.id().toString()
        ));
    }

    @GetMapping
    public ResponseEntity<?> list(@RequestParam(defaultValue="0") int page, @RequestParam(defaultValue="20") int size) {
        var tenantId = TenantContext.getTenantId();
        if (tenantId == null)
            return ResponseEntity.badRequest().body(Map.of("error", "Missing X-Tenant-Id header"));
        return ResponseEntity.ok(invoices.listByTenant(tenantId, page, size));
    }

    private static String sha256Hex(byte[] bytes){
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(bytes);
            return HexFormat.of().formatHex(digest);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 not available", e);
        }
    }
}