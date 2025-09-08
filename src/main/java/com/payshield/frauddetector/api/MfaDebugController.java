// ==============================================================================
// MFA Debug Controller - For Testing TOTP Issues
// File: src/main/java/com/payshield/frauddetector/api/MfaDebugController.java
// TEMPORARY: Remove this in production!
// ==============================================================================

package com.payshield.frauddetector.api;

import com.payshield.frauddetector.application.MfaService;
import com.payshield.frauddetector.config.TenantContext;
import com.payshield.frauddetector.infrastructure.encryption.FieldEncryptionService;
import com.payshield.frauddetector.infrastructure.jpa.*;
import com.payshield.frauddetector.infrastructure.mfa.TOTPService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.time.OffsetDateTime;
import java.util.*;

@RestController
@RequestMapping("/debug/mfa")
public class MfaDebugController {

    private static final Logger log = LoggerFactory.getLogger(MfaDebugController.class);

    private final TOTPService totpService;
    private final FieldEncryptionService encryptionService;
    private final SpringUserRepository userRepository;
    private final SpringMfaConfigurationRepository mfaConfigRepo;

    public MfaDebugController(TOTPService totpService, 
                             FieldEncryptionService encryptionService,
                             SpringUserRepository userRepository,
                             SpringMfaConfigurationRepository mfaConfigRepo) {
        this.totpService = totpService;
        this.encryptionService = encryptionService;
        this.userRepository = userRepository;
        this.mfaConfigRepo = mfaConfigRepo;
    }

    @PostMapping("/test-totp")
    public ResponseEntity<?> testTotpVerification(@RequestBody Map<String, String> request) {
        try {
            String secret = request.get("secret");
            String code = request.get("code");

            if (secret == null || code == null) {
                return ResponseEntity.badRequest().body(Map.of("error", "Missing secret or code"));
            }

            log.info("🧪 Testing TOTP - Secret length: {}, Code: '{}'", secret.length(), code);

            // Test with both verification methods
            boolean primaryResult = totpService.verifyCode(secret, code);
            boolean debugResult = totpService.verifyCodeWithDebug(secret, code);

            // Generate current expected code
            String currentCode = totpService.getCurrentCode(secret);
            long timeRemaining = totpService.getTimeUntilNextCode();

            Map<String, Object> response = new HashMap<>();
            response.put("primaryVerification", primaryResult);
            response.put("debugVerification", debugResult);
            response.put("providedCode", code);
            response.put("currentExpectedCode", currentCode);
            response.put("timeUntilNextCode", timeRemaining);
            response.put("secretLength", secret.length());
            response.put("timestamp", OffsetDateTime.now());

            return ResponseEntity.ok(response);

        } catch (Exception e) {
            log.error("TOTP test failed: {}", e.getMessage(), e);
            return ResponseEntity.internalServerError().body(Map.of(
                "error", "TOTP test failed",
                "message", e.getMessage()
            ));
        }
    }

    @GetMapping("/current-user-totp")
    public ResponseEntity<?> getCurrentUserTotpInfo() {
        try {
            UUID tenantId = TenantContext.getTenantId();
            Authentication auth = SecurityContextHolder.getContext().getAuthentication();
            
            if (tenantId == null || auth == null) {
                return ResponseEntity.badRequest().body(Map.of("error", "Missing authentication context"));
            }

            String email = auth.getName();
            UUID userId = getUserIdByEmail(email);

            Optional<MfaConfigurationEntity> config = mfaConfigRepo.findByUserIdAndTenantId(userId, tenantId);
            
            if (config.isEmpty()) {
                return ResponseEntity.badRequest().body(Map.of("error", "No MFA configuration found"));
            }

            MfaConfigurationEntity mfaConfig = config.get();

            // Decrypt the secret for testing
            String secret = encryptionService.decrypt(mfaConfig.getEncryptedSecret());
            String currentCode = totpService.getCurrentCode(secret);
            long timeRemaining = totpService.getTimeUntilNextCode();

            Map<String, Object> response = new HashMap<>();
            response.put("userId", userId.toString());
            response.put("email", email);
            response.put("isSetupComplete", mfaConfig.isSetupComplete());
            response.put("status", mfaConfig.getStatus().name());
            response.put("currentExpectedCode", currentCode);
            response.put("timeUntilNextCode", timeRemaining);
            response.put("secretLength", secret.length());
            response.put("encryptionKeyVersion", mfaConfig.getEncryptionKeyVersion());
            response.put("lastUsedAt", mfaConfig.getLastUsedAt());
            response.put("failedAttempts", mfaConfig.getFailedAttempts());
            response.put("timestamp", OffsetDateTime.now());

            // ⚠️ SECURITY WARNING: Only for debugging!
            response.put("secretPreview", secret.substring(0, 4) + "****");

            return ResponseEntity.ok(response);

        } catch (Exception e) {
            log.error("Failed to get current user TOTP info: {}", e.getMessage(), e);
            return ResponseEntity.internalServerError().body(Map.of(
                "error", "Failed to get TOTP info",
                "message", e.getMessage()
            ));
        }
    }

    @PostMapping("/verify-against-stored")
    public ResponseEntity<?> verifyAgainstStoredSecret(@RequestBody Map<String, String> request) {
        try {
            UUID tenantId = TenantContext.getTenantId();
            Authentication auth = SecurityContextHolder.getContext().getAuthentication();
            
            if (tenantId == null || auth == null) {
                return ResponseEntity.badRequest().body(Map.of("error", "Missing authentication context"));
            }

            String code = request.get("code");
            if (code == null) {
                return ResponseEntity.badRequest().body(Map.of("error", "Missing code"));
            }

            String email = auth.getName();
            UUID userId = getUserIdByEmail(email);

            Optional<MfaConfigurationEntity> config = mfaConfigRepo.findByUserIdAndTenantId(userId, tenantId);
            
            if (config.isEmpty()) {
                return ResponseEntity.badRequest().body(Map.of("error", "No MFA configuration found"));
            }

            // Decrypt the stored secret
            String secret = encryptionService.decrypt(config.get().getEncryptedSecret());

            // Test verification
            boolean isValid = totpService.verifyCode(secret, code);
            boolean isValidDebug = totpService.verifyCodeWithDebug(secret, code);
            
            // Generate current code for comparison
            String currentCode = totpService.getCurrentCode(secret);

            Map<String, Object> response = new HashMap<>();
            response.put("providedCode", code);
            response.put("currentExpectedCode", currentCode);
            response.put("verificationResult", isValid);
            response.put("debugVerificationResult", isValidDebug);
            response.put("codesMatch", code.equals(currentCode));
            response.put("timeUntilNext", totpService.getTimeUntilNextCode());
            response.put("timestamp", OffsetDateTime.now());

            return ResponseEntity.ok(response);

        } catch (Exception e) {
            log.error("Failed to verify against stored secret: {}", e.getMessage(), e);
            return ResponseEntity.internalServerError().body(Map.of(
                "error", "Verification test failed",
                "message", e.getMessage()
            ));
        }
    }

    @PostMapping("/encryption-test")
    public ResponseEntity<?> testEncryptionRoundTrip(@RequestBody Map<String, String> request) {
        try {
            String testData = request.getOrDefault("data", "test-secret-12345");

            // Test encryption round trip
            String encrypted = encryptionService.encrypt(testData);
            String decrypted = encryptionService.decrypt(encrypted);
            
            boolean roundTripSuccess = testData.equals(decrypted);

            Map<String, Object> response = new HashMap<>();
            response.put("originalData", testData);
            response.put("encryptedLength", encrypted.length());
            response.put("decryptedData", decrypted);
            response.put("roundTripSuccess", roundTripSuccess);
            response.put("keyVersion", encryptionService.getCurrentKeyVersion());

            return ResponseEntity.ok(response);

        } catch (Exception e) {
            log.error("Encryption test failed: {}", e.getMessage(), e);
            return ResponseEntity.internalServerError().body(Map.of(
                "error", "Encryption test failed",
                "message", e.getMessage()
            ));
        }
    }

    @PostMapping("/time-sync-test")
    public ResponseEntity<?> testTimeSync() {
        try {
            long currentTimeMillis = System.currentTimeMillis();
            long currentTimeSeconds = currentTimeMillis / 1000;
            long timeSlot = currentTimeSeconds / 30; // 30-second window
            long timeInSlot = currentTimeSeconds % 30;
            long timeUntilNext = 30 - timeInSlot;

            Map<String, Object> response = new HashMap<>();
            response.put("currentTimeMillis", currentTimeMillis);
            response.put("currentTimeSeconds", currentTimeSeconds);
            response.put("currentTimeSlot", timeSlot);
            response.put("timeInCurrentSlot", timeInSlot);
            response.put("timeUntilNextSlot", timeUntilNext);
            response.put("serverTime", OffsetDateTime.now().toString());

            return ResponseEntity.ok(response);

        } catch (Exception e) {
            log.error("Time sync test failed: {}", e.getMessage(), e);
            return ResponseEntity.internalServerError().body(Map.of(
                "error", "Time sync test failed",
                "message", e.getMessage()
            ));
        }
    }

    @PostMapping("/generate-test-codes")
    public ResponseEntity<?> generateTestCodes(@RequestBody Map<String, String> request) {
        try {
            String secret = request.get("secret");
            if (secret == null) {
                return ResponseEntity.badRequest().body(Map.of("error", "Missing secret"));
            }

            long currentTime = System.currentTimeMillis() / 1000;
            long currentSlot = currentTime / 30;

            Map<String, String> codes = new HashMap<>();
            
            // Generate codes for current and adjacent time slots
            for (int i = -2; i <= 2; i++) {
                long timeSlot = currentSlot + i;
                String code = totpService.getCurrentCode(secret);
                // Note: This is simplified - ideally we'd generate for specific time slots
                codes.put("slot_" + (currentSlot + i), code);
            }

            Map<String, Object> response = new HashMap<>();
            response.put("currentSlot", currentSlot);
            response.put("codes", codes);
            response.put("timeUntilNext", totpService.getTimeUntilNextCode());

            return ResponseEntity.ok(response);

        } catch (Exception e) {
            log.error("Test code generation failed: {}", e.getMessage(), e);
            return ResponseEntity.internalServerError().body(Map.of(
                "error", "Test code generation failed",
                "message", e.getMessage()
            ));
        }
    }

    private UUID getUserIdByEmail(String email) {
        UserEntity user = userRepository.findByEmail(email.toLowerCase())
                .orElseThrow(() -> new IllegalStateException("User not found: " + email));
        return user.getId();
    }
}