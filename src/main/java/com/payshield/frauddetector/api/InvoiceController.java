// ==============================================================================
// Step 5: Updated InvoiceController with Enhanced Security
// Replace your existing InvoiceController upload method with this enhanced version
// ==============================================================================

// src/main/java/com/payshield/frauddetector/api/InvoiceController.java

package com.payshield.frauddetector.api;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.payshield.frauddetector.api.dto.UploadInvoiceRequest;
import com.payshield.frauddetector.application.InvoiceDetectionService;
import com.payshield.frauddetector.application.UploadInvoiceCommand;
import com.payshield.frauddetector.config.TenantContext;
import com.payshield.frauddetector.domain.ports.InvoiceRepository;
import com.payshield.frauddetector.infrastructure.security.FileUploadSecurityService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MaxUploadSizeExceededException;
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
    private final FileUploadSecurityService fileSecurityService;
    private final ObjectMapper mapper = new ObjectMapper();

    public InvoiceController(InvoiceDetectionService service,
                             InvoiceRepository invoices,
                             FileUploadSecurityService fileSecurityService) {
        this.service = service;
        this.invoices = invoices;
        this.fileSecurityService = fileSecurityService;
    }

    @PostMapping(value = "/upload", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<?> upload(@RequestPart("file") MultipartFile file,
                                    @RequestPart(value="meta", required=false) String metaJson,
                                    @RequestHeader(value="Idempotency-Key", required=false) String idempotencyKey,
                                    @RequestHeader(value="X-Sender-Domain", required=false) String senderDomain) throws IOException {

        log.info("Invoice upload request - filename: {}, contentType: {}, size: {} bytes",
                file.getOriginalFilename(), file.getContentType(), file.getSize());

        UUID tenantId = TenantContext.getTenantId();
        if (tenantId == null) {
            log.error("No tenant ID in context");
            return ResponseEntity.badRequest().body(Map.of("error", "Missing tenant context"));
        }

        // ==========================================
        // ENHANCED SECURITY VALIDATION - Step 5
        // ==========================================

        log.info("Starting comprehensive file security validation...");
        FileUploadSecurityService.FileValidationResult validationResult = fileSecurityService.validateFile(file);

        if (!validationResult.isValid()) {
            log.error("File validation failed: {}", validationResult.getErrorMessage());
            return ResponseEntity.badRequest().body(Map.of(
                    "error", "File validation failed",
                    "message", validationResult.getErrorMessage(),
                    "code", "INVALID_FILE"
            ));
        }

        log.info("✅ File security validation passed for: {}", file.getOriginalFilename());

        // ==========================================
        // EXISTING LOGIC (Enhanced with better logging)
        // ==========================================

        // Parse meta JSON if provided
        UploadInvoiceRequest meta = null;
        if (metaJson != null && !metaJson.isBlank()) {
            try {
                meta = mapper.readValue(metaJson, UploadInvoiceRequest.class);
                log.info("Parsed meta: vendorName={}, currency={}", meta.vendorName, meta.currency);
            } catch (Exception e) {
                log.error("Failed to parse meta JSON: {}", metaJson, e);
                return ResponseEntity.badRequest().body(Map.of(
                        "error", "Invalid meta JSON",
                        "message", e.getMessage(),
                        "code", "INVALID_META"
                ));
            }
        }

        log.info("Processing upload for tenant: {}, vendor: {}", tenantId, meta != null ? meta.vendorName : "null");

        // Calculate file hash for deduplication
        String sha256 = sha256Hex(file.getBytes());
        log.info("File SHA256: {}", sha256);

        // Create command for processing
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

        try {
            var result = service.uploadAndDetect(cmd, sha256);
            log.info("Fraud detection completed - invoiceId: {}, alreadyExists: {}", result.id(), result.alreadyExists());

            return ResponseEntity.ok(Map.of(
                    "status", result.alreadyExists() ? "already_exists" : "created",
                    "id", result.id().toString(),
                    "message", result.alreadyExists() ?
                            "File already processed" :
                            "File uploaded and processed successfully"
            ));

        } catch (Exception e) {
            log.error("Error during fraud detection processing: {}", e.getMessage(), e);
            return ResponseEntity.internalServerError().body(Map.of(
                    "error", "Processing failed",
                    "message", "An error occurred while processing the file",
                    "code", "PROCESSING_ERROR"
            ));
        }
    }

    @GetMapping
    public ResponseEntity<?> list(@RequestParam(defaultValue="0") int page,
                                  @RequestParam(defaultValue="20") int size) {
        var tenantId = TenantContext.getTenantId();
        if (tenantId == null) {
            return ResponseEntity.badRequest().body(Map.of("error", "Missing tenant context"));
        }
        return ResponseEntity.ok(invoices.listByTenant(tenantId, page, size));
    }

    // ==========================================
    // ENHANCED ERROR HANDLING - Step 5
    // ==========================================

    /**
     * Handle file size limit exceeded exceptions
     */
    @ExceptionHandler(MaxUploadSizeExceededException.class)
    public ResponseEntity<?> handleFileSizeLimit(MaxUploadSizeExceededException ex) {
        log.error("File size limit exceeded: {}", ex.getMessage());
        return ResponseEntity.badRequest().body(Map.of(
                "error", "File too large",
                "message", "Maximum file size is 10MB",
                "code", "FILE_TOO_LARGE"
        ));
    }

    /**
     * Handle general multipart exceptions
     */
    @ExceptionHandler(org.springframework.web.multipart.MultipartException.class)
    public ResponseEntity<?> handleMultipartException(org.springframework.web.multipart.MultipartException ex) {
        log.error("Multipart upload error: {}", ex.getMessage());
        return ResponseEntity.badRequest().body(Map.of(
                "error", "Upload failed",
                "message", "Invalid multipart request",
                "code", "MULTIPART_ERROR"
        ));
    }

    /**
     * Handle I/O exceptions during file processing
     */
    @ExceptionHandler(IOException.class)
    public ResponseEntity<?> handleIOException(IOException ex) {
        log.error("I/O error during file processing: {}", ex.getMessage(), ex);
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(Map.of(
                "error", "File processing failed",
                "message", "Unable to process uploaded file",
                "code", "IO_ERROR"
        ));
    }

    // ==========================================
    // UTILITY METHODS
    // ==========================================

    private static String sha256Hex(byte[] bytes) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(bytes);
            return HexFormat.of().formatHex(digest);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 not available", e);
        }
    }
}