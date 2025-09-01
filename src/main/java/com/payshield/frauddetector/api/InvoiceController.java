// ==============================================================================
// Step 11: Complete InvoiceController with OpenAPI Documentation
// Replace your existing InvoiceController.java with this enhanced version
// ==============================================================================

package com.payshield.frauddetector.api;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.payshield.frauddetector.api.dto.UploadInvoiceRequest;
import com.payshield.frauddetector.application.InvoiceDetectionService;
import com.payshield.frauddetector.application.UploadInvoiceCommand;
import com.payshield.frauddetector.config.TenantContext;
import com.payshield.frauddetector.domain.ports.InvoiceRepository;
import com.payshield.frauddetector.infrastructure.security.FileUploadSecurityService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.ExampleObject;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
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
@Tag(name = "Invoice Processing", description = "Secure invoice upload and fraud detection with enterprise-grade security")
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
    @Operation(
            summary = "Upload invoice for fraud detection",
            description = """
            Upload a PDF invoice file for processing and fraud detection analysis.
            
            **Security Features:**
            - File size limited to 10MB
            - Only PDF files accepted
            - Real-time virus scanning with ClamAV
            - Content validation with Apache Tika
            - Duplicate detection via SHA-256 hashing
            - File signature validation (magic bytes)
            
            **Fraud Detection Engine:**
            - New vendor account detection
            - Bank account change monitoring  
            - Sender domain validation
            - Invoice format validation
            - Anomaly detection algorithms
            
            **Multi-Tenant Security:**
            - Tenant isolation enforced
            - Role-based access control
            - Comprehensive audit logging
            """
    )
    @SecurityRequirement(name = "Bearer Authentication")
    @ApiResponses({
            @ApiResponse(
                    responseCode = "200",
                    description = "File uploaded and processed successfully",
                    content = @Content(
                            mediaType = "application/json",
                            examples = {
                                    @ExampleObject(
                                            name = "New Invoice Processed",
                                            description = "Successfully processed new invoice",
                                            value = """
                            {
                                "status": "created",
                                "id": "123e4567-e89b-12d3-a456-426614174000",
                                "message": "File uploaded and processed successfully"
                            }
                            """
                                    ),
                                    @ExampleObject(
                                            name = "Duplicate Invoice Detected",
                                            description = "Invoice already exists (detected by SHA-256 hash)",
                                            value = """
                            {
                                "status": "already_exists",
                                "id": "123e4567-e89b-12d3-a456-426614174000",
                                "message": "File already processed"
                            }
                            """
                                    )
                            }
                    )
            ),
            @ApiResponse(
                    responseCode = "400",
                    description = "File validation failed",
                    content = @Content(
                            mediaType = "application/json",
                            examples = {
                                    @ExampleObject(
                                            name = "Invalid File Type",
                                            value = """
                            {
                                "error": "File validation failed",
                                "message": "Only PDF files are allowed (declared type: image/jpeg)",
                                "code": "INVALID_FILE"
                            }
                            """
                                    ),
                                    @ExampleObject(
                                            name = "Virus Detected",
                                            value = """
                            {
                                "error": "File validation failed",
                                "message": "File failed security scan - malware detected",
                                "code": "INVALID_FILE"
                            }
                            """
                                    ),
                                    @ExampleObject(
                                            name = "Invalid Metadata",
                                            value = """
                            {
                                "error": "Invalid meta JSON",
                                "message": "Unexpected character at position 15",
                                "code": "INVALID_META"
                            }
                            """
                                    )
                            }
                    )
            ),
            @ApiResponse(
                    responseCode = "401",
                    description = "Authentication required",
                    content = @Content(
                            mediaType = "application/json",
                            examples = @ExampleObject(value = """
                    {
                        "error": "Unauthorized",
                        "message": "Valid Bearer token required"
                    }
                    """)
                    )
            ),
            @ApiResponse(
                    responseCode = "413",
                    description = "File too large",
                    content = @Content(
                            mediaType = "application/json",
                            examples = @ExampleObject(value = """
                    {
                        "error": "File too large",
                        "message": "Maximum file size is 10MB",
                        "code": "FILE_TOO_LARGE"
                    }
                    """)
                    )
            ),
            @ApiResponse(
                    responseCode = "500",
                    description = "Internal processing error",
                    content = @Content(
                            mediaType = "application/json",
                            examples = @ExampleObject(value = """
                    {
                        "error": "Processing failed",
                        "message": "An error occurred while processing the file",
                        "code": "PROCESSING_ERROR"
                    }
                    """)
                    )
            )
    })
    public ResponseEntity<?> upload(
            @Parameter(
                    description = "PDF invoice file to upload (max 10MB)",
                    required = true,
                    content = @Content(mediaType = "application/pdf"),
                    example = "invoice.pdf"
            )
            @RequestPart("file") MultipartFile file,

            @Parameter(
                    description = """
                    Invoice metadata in JSON format containing vendor information and currency.
                    Optional but recommended for accurate fraud detection.
                    """,
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = UploadInvoiceRequest.class),
                            examples = @ExampleObject(value = """
                        {
                            "vendorName": "Acme Corporation Ltd",
                            "currency": "USD"
                        }
                        """)
                    )
            )
            @RequestPart(value="meta", required=false) String metaJson,

            @Parameter(
                    description = """
                    Idempotency key for duplicate request prevention. 
                    If not provided, the file SHA-256 hash will be used.
                    """,
                    example = "invoice-2024-001-acme"
            )
            @RequestHeader(value="Idempotency-Key", required=false) String idempotencyKey,

            @Parameter(
                    description = """
                    Email domain of the invoice sender for domain validation.
                    Used by fraud detection to verify sender authenticity.
                    """,
                    example = "acme.com"
            )
            @RequestHeader(value="X-Sender-Domain", required=false) String senderDomain
    ) throws IOException {

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
        // METADATA PARSING AND VALIDATION
        // ==========================================

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

        // ==========================================
        // FILE PROCESSING AND FRAUD DETECTION
        // ==========================================

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
    @Operation(
            summary = "List invoices for current tenant",
            description = """
            Retrieve a paginated list of invoices for the authenticated user's tenant.
            Results are sorted by received date (newest first) and include basic invoice information.
            """
    )
    @SecurityRequirement(name = "Bearer Authentication")
    @ApiResponses({
            @ApiResponse(
                    responseCode = "200",
                    description = "Invoices retrieved successfully",
                    content = @Content(
                            mediaType = "application/json",
                            examples = @ExampleObject(value = """
                    [
                        {
                            "id": "123e4567-e89b-12d3-a456-426614174000",
                            "tenantId": "00000000-0000-0000-0000-000000000001",
                            "vendorId": "vendor-uuid-here",
                            "amount": 1500.00,
                            "currency": "USD",
                            "receivedAt": "2024-09-01T20:50:42Z",
                            "bankLast4": "1234",
                            "fileSha256": "6348cd89142512bb6debf988e934cacad1a678c42ef2d4f9e3aa1b504f05c149"
                        },
                        {
                            "id": "456e7890-e89b-12d3-a456-426614174001",
                            "tenantId": "00000000-0000-0000-0000-000000000001", 
                            "vendorId": "vendor-uuid-here-2",
                            "amount": 2500.00,
                            "currency": "EUR",
                            "receivedAt": "2024-08-28T14:30:15Z",
                            "bankLast4": "5678",
                            "fileSha256": "7459de90253623cc7efb999f045cdbecd2b789d53fg3e5g0f4bb2c615g06d250"
                        }
                    ]
                    """)
                    )
            ),
            @ApiResponse(
                    responseCode = "400",
                    description = "Missing tenant context",
                    content = @Content(
                            mediaType = "application/json",
                            examples = @ExampleObject(value = """
                    {
                        "error": "Missing tenant context"
                    }
                    """)
                    )
            ),
            @ApiResponse(
                    responseCode = "401",
                    description = "Authentication required",
                    content = @Content(
                            mediaType = "application/json",
                            examples = @ExampleObject(value = """
                    {
                        "error": "Unauthorized",
                        "message": "Valid Bearer token required"
                    }
                    """)
                    )
            )
    })
    public ResponseEntity<?> list(
            @Parameter(
                    description = "Page number for pagination (0-based)",
                    example = "0"
            )
            @RequestParam(defaultValue="0") int page,

            @Parameter(
                    description = "Number of invoices per page",
                    example = "20"
            )
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
    @ApiResponse(
            responseCode = "413",
            description = "File size limit exceeded",
            content = @Content(
                    mediaType = "application/json",
                    examples = @ExampleObject(value = """
                {
                    "error": "File too large",
                    "message": "Maximum file size is 10MB",
                    "code": "FILE_TOO_LARGE"
                }
                """)
            )
    )
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
    @ApiResponse(
            responseCode = "400",
            description = "Invalid multipart request",
            content = @Content(
                    mediaType = "application/json",
                    examples = @ExampleObject(value = """
                {
                    "error": "Upload failed",
                    "message": "Invalid multipart request",
                    "code": "MULTIPART_ERROR"
                }
                """)
            )
    )
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
    @ApiResponse(
            responseCode = "500",
            description = "File processing error",
            content = @Content(
                    mediaType = "application/json",
                    examples = @ExampleObject(value = """
                {
                    "error": "File processing failed",
                    "message": "Unable to process uploaded file",
                    "code": "IO_ERROR"
                }
                """)
            )
    )
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