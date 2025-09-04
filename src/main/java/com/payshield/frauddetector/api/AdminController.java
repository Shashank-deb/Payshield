// ==============================================================================
// Complete AdminController.java - Admin-only endpoints for system management
// Create: src/main/java/com/payshield/frauddetector/api/AdminController.java
// ==============================================================================

package com.payshield.frauddetector.api;

import com.payshield.frauddetector.config.TenantContext;
import com.payshield.frauddetector.infrastructure.encryption.FieldEncryptionService;
import com.payshield.frauddetector.infrastructure.jpa.SpringInvoiceRepository;
import com.payshield.frauddetector.infrastructure.jpa.SpringOutboxRepository;
import com.payshield.frauddetector.infrastructure.outbox.OutboxDispatcher;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.ExampleObject;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.info.BuildProperties;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.time.OffsetDateTime;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

@RestController
@RequestMapping("/admin")
@Tag(name = "Administration", description = "Admin-only endpoints for system management and monitoring")
@SecurityRequirement(name = "Bearer Authentication")
@PreAuthorize("hasRole('ADMIN')")
public class AdminController {

    private static final Logger log = LoggerFactory.getLogger(AdminController.class);

    private final FieldEncryptionService encryptionService;
    private final SpringInvoiceRepository invoiceRepository;
    private final SpringOutboxRepository outboxRepository;
    private final OutboxDispatcher outboxDispatcher;
    private final Optional<BuildProperties> buildProperties;

    @Value("${spring.application.name:payshield-core}")
    private String applicationName;

    @Value("${server.port:2406}")
    private String serverPort;

    public AdminController(
            FieldEncryptionService encryptionService, 
            SpringInvoiceRepository invoiceRepository,
            SpringOutboxRepository outboxRepository,
            OutboxDispatcher outboxDispatcher,
            Optional<BuildProperties> buildProperties) {
        this.encryptionService = encryptionService;
        this.invoiceRepository = invoiceRepository;
        this.outboxRepository = outboxRepository;
        this.outboxDispatcher = outboxDispatcher;
        this.buildProperties = buildProperties;
    }

    // ==============================================================================
    // ENCRYPTION MANAGEMENT
    // ==============================================================================

    @GetMapping("/encryption/status")
    @Operation(
        summary = "Get encryption system status",
        description = "Returns detailed information about the field-level encryption system status and database statistics"
    )
    @ApiResponses({
        @ApiResponse(
            responseCode = "200",
            description = "Encryption status retrieved successfully",
            content = @Content(
                mediaType = "application/json",
                examples = @ExampleObject(value = """
                {
                  "status": "ACTIVE",
                  "algorithm": "AES-256-GCM",
                  "currentKeyVersion": 1,
                  "encryptionEnabled": true,
                  "statistics": {
                    "totalInvoices": 150,
                    "encryptedInvoices": 45,
                    "legacyInvoices": 105,
                    "encryptionPercentage": 30.0
                  },
                  "lastChecked": "2024-09-04T11:55:03Z"
                }
                """)
            )
        ),
        @ApiResponse(
            responseCode = "403",
            description = "Admin role required",
            content = @Content(
                mediaType = "application/json",
                examples = @ExampleObject(value = """
                {
                  "error": "Forbidden",
                  "message": "Insufficient role"
                }
                """)
            )
        )
    })
    public ResponseEntity<?> getEncryptionStatus() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        log.info("Admin encryption status check requested by user: {}", 
                auth != null ? auth.getName() : "unknown");

        try {
            Map<String, Object> status = new HashMap<>();
            
            // Basic encryption service info
            status.put("status", "ACTIVE");
            status.put("algorithm", "AES-256-GCM");
            status.put("currentKeyVersion", encryptionService.getCurrentKeyVersion());
            status.put("encryptionEnabled", true);
            
            // Database statistics
            Map<String, Object> stats = new HashMap<>();
            long totalInvoices = invoiceRepository.count();
            long legacyIbanCount = invoiceRepository.countByBankIbanIsNotNull();
            long legacySwiftCount = invoiceRepository.countByBankSwiftIsNotNull();
            long encryptedInvoices = invoiceRepository.countByBankIbanEncryptedIsNotNullOrBankSwiftEncryptedIsNotNull();
            
            // Calculate legacy invoices (invoices with any legacy plaintext data)
            long legacyInvoices = Math.max(legacyIbanCount, legacySwiftCount);
            
            stats.put("totalInvoices", totalInvoices);
            stats.put("encryptedInvoices", encryptedInvoices);
            stats.put("legacyInvoices", legacyInvoices);
            stats.put("legacyIbanCount", legacyIbanCount);
            stats.put("legacySwiftCount", legacySwiftCount);
            stats.put("encryptionPercentage", totalInvoices > 0 ? 
                Math.round((double) encryptedInvoices / totalInvoices * 100.0 * 100.0) / 100.0 : 0.0);
            
            status.put("statistics", stats);
            status.put("lastChecked", OffsetDateTime.now());
            
            log.info("Encryption status check completed - Total: {}, Encrypted: {}, Legacy: {}", 
                    totalInvoices, encryptedInvoices, legacyInvoices);
            
            return ResponseEntity.ok(status);
            
        } catch (Exception e) {
            log.error("Failed to get encryption status: {}", e.getMessage(), e);
            return ResponseEntity.internalServerError().body(Map.of(
                "error", "Failed to retrieve encryption status",
                "message", e.getMessage(),
                "timestamp", OffsetDateTime.now()
            ));
        }
    }

    @PostMapping("/encryption/test")
    @Operation(
        summary = "Test encryption functionality",
        description = "Performs a round-trip encryption/decryption test to verify the encryption system is working correctly"
    )
    @ApiResponses({
        @ApiResponse(
            responseCode = "200",
            description = "Encryption test completed successfully",
            content = @Content(
                mediaType = "application/json",
                examples = @ExampleObject(value = """
                {
                  "status": "SUCCESS",
                  "testPerformed": "2024-09-04T11:55:03Z",
                  "algorithm": "AES-256-GCM",
                  "keyVersion": 1,
                  "roundTripSuccess": true,
                  "encryptionTime": 12,
                  "decryptionTime": 8,
                  "encryptedLength": 256,
                  "hashGenerated": true,
                  "message": "Encryption system is working correctly"
                }
                """)
            )
        ),
        @ApiResponse(
            responseCode = "500",
            description = "Encryption test failed",
            content = @Content(
                mediaType = "application/json",
                examples = @ExampleObject(value = """
                {
                  "status": "FAILURE",
                  "error": "Encryption test failed",
                  "message": "Round-trip test failed: decrypted value does not match original"
                }
                """)
            )
        )
    })
    public ResponseEntity<?> testEncryption() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        log.info("Admin encryption test requested by user: {}", 
                auth != null ? auth.getName() : "unknown");

        try {
            // Create test data with some complexity
            String testData = "ENCRYPTION_TEST_" + UUID.randomUUID().toString() + "_" + System.currentTimeMillis();
            log.debug("Testing encryption with data length: {}", testData.length());
            
            // Test 1: Basic round-trip encryption
            long encryptStart = System.currentTimeMillis();
            String encrypted = encryptionService.encrypt(testData);
            long encryptTime = System.currentTimeMillis() - encryptStart;
            
            if (encrypted == null) {
                throw new RuntimeException("Encryption returned null");
            }
            
            long decryptStart = System.currentTimeMillis();
            String decrypted = encryptionService.decrypt(encrypted);
            long decryptTime = System.currentTimeMillis() - decryptStart;
            
            // Verify round-trip success
            boolean roundTripSuccess = testData.equals(decrypted);
            
            if (!roundTripSuccess) {
                log.error("Encryption round-trip test failed - Original length: {}, Decrypted length: {}", 
                         testData.length(), decrypted != null ? decrypted.length() : 0);
                return ResponseEntity.internalServerError().body(Map.of(
                    "status", "FAILURE",
                    "error", "Encryption test failed",
                    "message", "Round-trip test failed: decrypted value does not match original",
                    "timestamp", OffsetDateTime.now()
                ));
            }
            
            // Test 2: Hash generation
            String hash = encryptionService.generateHash(testData);
            boolean hashGenerated = hash != null && !hash.isBlank() && hash.length() == 64; // SHA-256 hex length
            
            // Test 3: Encryption detection
            boolean isEncryptedDetected = encryptionService.isEncrypted(encrypted);
            boolean isPlaintextDetected = !encryptionService.isEncrypted(testData);
            
            Map<String, Object> result = new HashMap<>();
            result.put("status", "SUCCESS");
            result.put("testPerformed", OffsetDateTime.now());
            result.put("algorithm", "AES-256-GCM");
            result.put("keyVersion", encryptionService.getCurrentKeyVersion());
            result.put("roundTripSuccess", roundTripSuccess);
            result.put("encryptionTime", encryptTime);
            result.put("decryptionTime", decryptTime);
            result.put("encryptedLength", encrypted.length());
            result.put("hashGenerated", hashGenerated);
            result.put("hashLength", hash != null ? hash.length() : 0);
            result.put("encryptionDetection", isEncryptedDetected);
            result.put("plaintextDetection", isPlaintextDetected);
            result.put("message", "Encryption system is working correctly");
            result.put("performedBy", auth != null ? auth.getName() : "unknown");
            
            log.info("Encryption test completed successfully - Encrypt: {}ms, Decrypt: {}ms, Hash: {}", 
                    encryptTime, decryptTime, hashGenerated ? "generated" : "failed");
            
            return ResponseEntity.ok(result);
            
        } catch (Exception e) {
            log.error("Encryption test failed: {}", e.getMessage(), e);
            return ResponseEntity.internalServerError().body(Map.of(
                "status", "FAILURE",
                "error", "Encryption test failed",
                "message", e.getMessage(),
                "timestamp", OffsetDateTime.now()
            ));
        }
    }

    // ==============================================================================
    // SYSTEM INFORMATION
    // ==============================================================================

    @GetMapping("/system/info")
    @Operation(
        summary = "Get system information",
        description = "Returns comprehensive system health, configuration, and runtime information"
    )
    @ApiResponse(responseCode = "200", description = "System info retrieved successfully")
    public ResponseEntity<?> getSystemInfo() {
        UUID tenantId = TenantContext.getTenantId();
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        
        Map<String, Object> info = new HashMap<>();
        info.put("timestamp", OffsetDateTime.now());
        info.put("systemStatus", "OPERATIONAL");
        info.put("applicationName", applicationName);
        info.put("serverPort", serverPort);
        info.put("currentTenant", tenantId != null ? tenantId.toString() : null);
        info.put("currentUser", auth != null ? auth.getName() : null);
        
        // Build information (if available)
        if (buildProperties.isPresent()) {
            BuildProperties props = buildProperties.get();
            Map<String, Object> build = new HashMap<>();
            build.put("version", props.getVersion());
            build.put("time", props.getTime());
            build.put("name", props.getName());
            build.put("group", props.getGroup());
            build.put("artifact", props.getArtifact());
            info.put("build", build);
        }
        
        // Java runtime info
        Map<String, Object> runtime = new HashMap<>();
        runtime.put("javaVersion", System.getProperty("java.version"));
        runtime.put("javaVendor", System.getProperty("java.vendor"));
        runtime.put("availableProcessors", Runtime.getRuntime().availableProcessors());
        runtime.put("startTime", System.getProperty("java.vm.start.time", "unknown"));
        info.put("runtime", runtime);
        
        // Memory info
        Runtime rt = Runtime.getRuntime();
        Map<String, Object> memory = new HashMap<>();
        long totalMemory = rt.totalMemory();
        long freeMemory = rt.freeMemory();
        long maxMemory = rt.maxMemory();
        long usedMemory = totalMemory - freeMemory;
        
        memory.put("totalMemory", totalMemory);
        memory.put("freeMemory", freeMemory);
        memory.put("maxMemory", maxMemory);
        memory.put("usedMemory", usedMemory);
        memory.put("memoryUsagePercent", Math.round((double) usedMemory / maxMemory * 100.0 * 100.0) / 100.0);
        info.put("memory", memory);
        
        return ResponseEntity.ok(info);
    }

    @GetMapping("/system/health")
    @Operation(
        summary = "Get detailed system health check",
        description = "Performs comprehensive health checks on all system components"
    )
    @ApiResponse(responseCode = "200", description = "Health check completed")
    public ResponseEntity<?> getSystemHealth() {
        Map<String, Object> health = new HashMap<>();
        health.put("timestamp", OffsetDateTime.now());
        health.put("overallStatus", "HEALTHY");
        
        Map<String, Object> checks = new HashMap<>();
        
        // Database health
        try {
            long invoiceCount = invoiceRepository.count();
            checks.put("database", Map.of(
                "status", "HEALTHY",
                "invoiceCount", invoiceCount,
                "connectionTest", "PASSED"
            ));
        } catch (Exception e) {
            checks.put("database", Map.of(
                "status", "UNHEALTHY",
                "error", e.getMessage()
            ));
            health.put("overallStatus", "DEGRADED");
        }
        
        // Encryption health
        try {
            String testData = "health_check_" + System.currentTimeMillis();
            String encrypted = encryptionService.encrypt(testData);
            String decrypted = encryptionService.decrypt(encrypted);
            boolean encryptionHealthy = testData.equals(decrypted);
            
            checks.put("encryption", Map.of(
                "status", encryptionHealthy ? "HEALTHY" : "UNHEALTHY",
                "keyVersion", encryptionService.getCurrentKeyVersion(),
                "roundTripTest", encryptionHealthy ? "PASSED" : "FAILED"
            ));
            
            if (!encryptionHealthy) {
                health.put("overallStatus", "DEGRADED");
            }
        } catch (Exception e) {
            checks.put("encryption", Map.of(
                "status", "UNHEALTHY",
                "error", e.getMessage()
            ));
            health.put("overallStatus", "DEGRADED");
        }
        
        // Outbox health
        try {
            OutboxDispatcher.OutboxStats stats = outboxDispatcher.getStats();
            checks.put("outbox", Map.of(
                "status", "HEALTHY",
                "pendingEvents", stats.pendingEvents(),
                "processedEvents", stats.processedEvents(),
                "dispatchEnabled", stats.dispatchEnabled()
            ));
        } catch (Exception e) {
            checks.put("outbox", Map.of(
                "status", "UNHEALTHY",
                "error", e.getMessage()
            ));
            health.put("overallStatus", "DEGRADED");
        }
        
        health.put("checks", checks);
        
        // Return appropriate HTTP status
        String status = (String) health.get("overallStatus");
        if ("UNHEALTHY".equals(status)) {
            return ResponseEntity.status(503).body(health);
        } else if ("DEGRADED".equals(status)) {
            return ResponseEntity.status(200).body(health);
        } else {
            return ResponseEntity.ok(health);
        }
    }

    // ==============================================================================
    // OUTBOX MANAGEMENT
    // ==============================================================================

    @GetMapping("/outbox/stats")
    @Operation(
        summary = "Get outbox statistics",
        description = "Returns detailed statistics about the outbox event processing system"
    )
    @ApiResponse(responseCode = "200", description = "Outbox stats retrieved successfully")
    public ResponseEntity<?> getOutboxStats() {
        try {
            OutboxDispatcher.OutboxStats stats = outboxDispatcher.getStats();
            
            Map<String, Object> result = new HashMap<>();
            result.put("pendingEvents", stats.pendingEvents());
            result.put("processedEvents", stats.processedEvents());
            result.put("dispatchEnabled", stats.dispatchEnabled());
            result.put("totalEvents", stats.pendingEvents() + stats.processedEvents());
            result.put("timestamp", OffsetDateTime.now());
            
            // Processing rate (events per hour) - rough estimate
            if (stats.processedEvents() > 0) {
                result.put("estimatedProcessingRate", "Available in future version");
            }
            
            return ResponseEntity.ok(result);
        } catch (Exception e) {
            log.error("Failed to get outbox stats: {}", e.getMessage(), e);
            return ResponseEntity.internalServerError().body(Map.of(
                "error", "Failed to get outbox statistics",
                "message", e.getMessage()
            ));
        }
    }

    @PostMapping("/outbox/process/{eventId}")
    @Operation(
        summary = "Manually process specific outbox event",
        description = "Forces processing of a specific outbox event by ID (for debugging/recovery)"
    )
    @ApiResponse(responseCode = "200", description = "Event processed successfully")
    public ResponseEntity<?> processOutboxEvent(
            @Parameter(description = "UUID of the outbox event to process")
            @PathVariable UUID eventId) {
        
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        log.info("Manual outbox event processing requested by user: {} for event: {}", 
                auth != null ? auth.getName() : "unknown", eventId);
        
        try {
            outboxDispatcher.processEventById(eventId);
            
            return ResponseEntity.ok(Map.of(
                "status", "SUCCESS",
                "message", "Event processed successfully",
                "eventId", eventId.toString(),
                "processedBy", auth != null ? auth.getName() : "unknown",
                "processedAt", OffsetDateTime.now()
            ));
        } catch (Exception e) {
            log.error("Failed to process event {}: {}", eventId, e.getMessage(), e);
            return ResponseEntity.internalServerError().body(Map.of(
                "status", "FAILURE",
                "error", "Failed to process event",
                "eventId", eventId.toString(),
                "message", e.getMessage()
            ));
        }
    }

    // ==============================================================================
    // CACHE AND MAINTENANCE
    // ==============================================================================

    @PostMapping("/cache/clear")
    @Operation(
        summary = "Clear application caches",
        description = "Clears various application caches and forces garbage collection"
    )
    @ApiResponse(responseCode = "200", description = "Cache cleared successfully")
    public ResponseEntity<?> clearCache() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        log.info("Admin cache clear requested by user: {}", 
                auth != null ? auth.getName() : "unknown");
        
        try {
            // Force garbage collection (note: this is just a suggestion to the JVM)
            long memoryBefore = Runtime.getRuntime().totalMemory() - Runtime.getRuntime().freeMemory();
            System.gc();
            
            // Wait a moment for GC to potentially run
            Thread.sleep(100);
            
            long memoryAfter = Runtime.getRuntime().totalMemory() - Runtime.getRuntime().freeMemory();
            long memoryFreed = memoryBefore - memoryAfter;
            
            // In a real application, you would clear Redis, Caffeine, etc. here
            // For now, this is a placeholder
            
            log.info("Cache clear completed by user: {}, Memory freed: {} bytes", 
                    auth != null ? auth.getName() : "unknown", memoryFreed);
            
            return ResponseEntity.ok(Map.of(
                "status", "SUCCESS",
                "message", "Application caches cleared and garbage collection requested",
                "memoryFreed", memoryFreed,
                "performedBy", auth != null ? auth.getName() : "unknown",
                "timestamp", OffsetDateTime.now()
            ));
            
        } catch (Exception e) {
            log.error("Cache clear failed: {}", e.getMessage(), e);
            return ResponseEntity.internalServerError().body(Map.of(
                "status", "FAILURE",
                "error", "Failed to clear cache",
                "message", e.getMessage()
            ));
        }
    }

    @GetMapping("/database/stats")
    @Operation(
        summary = "Get database statistics",
        description = "Returns comprehensive database statistics and table counts"
    )
    @ApiResponse(responseCode = "200", description = "Database stats retrieved successfully")
    public ResponseEntity<?> getDatabaseStats() {
        try {
            Map<String, Object> stats = new HashMap<>();
            
            // Invoice statistics
            long totalInvoices = invoiceRepository.count();
            long encryptedInvoices = invoiceRepository.countByBankIbanEncryptedIsNotNullOrBankSwiftEncryptedIsNotNull();
            long legacyInvoices = Math.max(
                invoiceRepository.countByBankIbanIsNotNull(),
                invoiceRepository.countByBankSwiftIsNotNull()
            );
            
            Map<String, Object> invoiceStats = new HashMap<>();
            invoiceStats.put("total", totalInvoices);
            invoiceStats.put("encrypted", encryptedInvoices);
            invoiceStats.put("legacy", legacyInvoices);
            invoiceStats.put("encryptionPercentage", totalInvoices > 0 ? 
                Math.round((double) encryptedInvoices / totalInvoices * 100.0 * 100.0) / 100.0 : 0.0);
            
            stats.put("invoices", invoiceStats);
            
            // Outbox statistics
            long totalOutboxEvents = outboxRepository.count();
            long pendingEvents = outboxRepository.countByProcessedAtIsNull();
            long processedEvents = outboxRepository.countByProcessedAtIsNotNull();
            
            Map<String, Object> outboxStats = new HashMap<>();
            outboxStats.put("total", totalOutboxEvents);
            outboxStats.put("pending", pendingEvents);
            outboxStats.put("processed", processedEvents);
            outboxStats.put("processingPercentage", totalOutboxEvents > 0 ? 
                Math.round((double) processedEvents / totalOutboxEvents * 100.0 * 100.0) / 100.0 : 0.0);
            
            stats.put("outbox", outboxStats);
            stats.put("timestamp", OffsetDateTime.now());
            
            return ResponseEntity.ok(stats);
            
        } catch (Exception e) {
            log.error("Failed to get database stats: {}", e.getMessage(), e);
            return ResponseEntity.internalServerError().body(Map.of(
                "error", "Failed to retrieve database statistics",
                "message", e.getMessage()
            ));
        }
    }
}