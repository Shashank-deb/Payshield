package com.payshield.frauddetector.api;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.payshield.frauddetector.api.dto.UploadInvoiceRequest;
import com.payshield.frauddetector.application.InvoiceDetectionService;
import com.payshield.frauddetector.application.UploadInvoiceCommand;
import com.payshield.frauddetector.config.TenantContext;
import com.payshield.frauddetector.domain.ports.InvoiceRepository;
import jakarta.validation.Valid;
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

    private final InvoiceDetectionService service;
    private final InvoiceRepository invoices;
    private final ObjectMapper mapper = new ObjectMapper();

    public InvoiceController(InvoiceDetectionService service, InvoiceRepository invoices) {
        this.service = service; this.invoices = invoices;
    }

    @PostMapping(path="/upload", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<?> upload(@RequestPart("file") MultipartFile file,
                                    @RequestPart(value="meta", required=false) @Valid UploadInvoiceRequest meta,
                                    @RequestHeader(value="Idempotency-Key", required=false) String idempotencyKey,
                                    @RequestHeader(value="X-Sender-Domain", required=false) String senderDomain) throws IOException {
        UUID tenantId = TenantContext.getTenantId();
        if (tenantId == null)
            return ResponseEntity.badRequest().body(Map.of("error", "Missing X-Tenant-Id header"));

        String sha256 = sha256Hex(file.getBytes());
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

        var result = service.uploadAndDetect(cmd, sha256);

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
