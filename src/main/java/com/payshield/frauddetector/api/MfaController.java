// ==============================================================================
// MFA API Controller - Complete Multi-Factor Authentication REST API
// File: src/main/java/com/payshield/frauddetector/api/MfaController.java
// ==============================================================================

package com.payshield.frauddetector.api;

import com.payshield.frauddetector.application.MfaService;
import com.payshield.frauddetector.config.TenantContext;
import com.payshield.frauddetector.infrastructure.jpa.SpringUserRepository;
import com.payshield.frauddetector.infrastructure.jpa.UserEntity;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.ExampleObject;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.time.OffsetDateTime;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@RestController
@RequestMapping("/mfa")
@Tag(name = "Multi-Factor Authentication", description = "TOTP-based MFA setup, verification, and management")
@SecurityRequirement(name = "Bearer Authentication")
public class MfaController {

    private static final Logger log = LoggerFactory.getLogger(MfaController.class);

    private final MfaService mfaService;
    private final SpringUserRepository userRepository;

    public MfaController(MfaService mfaService, SpringUserRepository userRepository) {
        this.mfaService = mfaService;
        this.userRepository = userRepository;
    }

    // ==========================================================================
    // MFA SETUP ENDPOINTS
    // ==========================================================================

    @PostMapping("/setup/initiate")
    @Operation(
        summary = "Initiate MFA setup",
        description = """
        Begins the MFA setup process for the authenticated user by generating:
        - TOTP shared secret
        - QR code for authenticator app setup
        - Backup recovery codes
        
        The user must complete setup by verifying their first TOTP code.
        """
    )
    @ApiResponses({
        @ApiResponse(
            responseCode = "200", 
            description = "MFA setup initiated successfully",
            content = @Content(
                mediaType = "application/json",
                examples = @ExampleObject(value = """
                {
                  "qrCodeUri": "otpauth://totp/PayShield:user@example.com?secret=...",
                  "qrCodeImage": "data:image/png;base64,iVBORw0KGgoAAAANSU...",
                  "backupCodes": ["ABCD1234", "EFGH5678", "..."],
                  "instructions": "Scan QR code with authenticator app, then verify with first code"
                }
                """)
            )
        ),
        @ApiResponse(responseCode = "400", description = "MFA already configured for user"),
        @ApiResponse(responseCode = "401", description = "Authentication required")
    })
    public ResponseEntity<?> initiateMfaSetup(HttpServletRequest request) {
        UUID tenantId = TenantContext.getTenantId();
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        
        if (tenantId == null || auth == null) {
            return ResponseEntity.badRequest().body(Map.of("error", "Missing authentication context"));
        }

        try {
            String email = auth.getName();
            UUID userId = getUserIdByEmail(email);

            log.info("Initiating MFA setup for user: {} ({})", email, userId);

            MfaService.MfaSetupResult result = mfaService.initiateMfaSetup(userId, tenantId, email);

            Map<String, Object> response = new HashMap<>();
            response.put("qrCodeUri", result.getQrCodeUri());
            response.put("qrCodeImage", "data:image/png;base64," + result.getQrCodeImage());
            response.put("backupCodes", result.getBackupCodes());
            response.put("instructions", "Scan the QR code with your authenticator app, then verify with the first TOTP code");
            response.put("setupExpires", OffsetDateTime.now().plusMinutes(15).toString());

            log.info("✅ MFA setup initiated for user: {}", email);
            return ResponseEntity.ok(response);

        } catch (IllegalStateException e) {
            log.warn("MFA setup error for user {}: {}", auth.getName(), e.getMessage());
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        } catch (Exception e) {
            log.error("❌ Failed to initiate MFA setup for user {}: {}", auth.getName(), e.getMessage(), e);
            return ResponseEntity.internalServerError().body(
                Map.of("error", "Failed to initiate MFA setup", "message", e.getMessage())
            );
        }
    }

    @PostMapping("/setup/complete")
    @Operation(
        summary = "Complete MFA setup",
        description = """
        Completes MFA setup by verifying the first TOTP code from the user's authenticator app.
        On success, MFA becomes active for the user's account.
        
        Optionally creates a trusted device to bypass MFA for future logins from the same device.
        """
    )
    @ApiResponses({
        @ApiResponse(
            responseCode = "200",
            description = "MFA setup completed successfully",
            content = @Content(
                mediaType = "application/json",
                examples = @ExampleObject(value = """
                {
                  "success": true,
                  "message": "MFA setup completed successfully",
                  "trustedDevice": true,
                  "deviceId": "uuid-here"
                }
                """)
            )
        ),
        @ApiResponse(responseCode = "400", description = "Invalid TOTP code or setup not initiated"),
        @ApiResponse(responseCode = "401", description = "Authentication required")
    })
    public ResponseEntity<?> completeMfaSetup(
        @io.swagger.v3.oas.annotations.parameters.RequestBody(
            description = "TOTP verification request",
            content = @Content(
                mediaType = "application/json",
                examples = @ExampleObject(value = """
                {
                  "totpCode": "123456",
                  "trustDevice": true,
                  "deviceName": "My Laptop"
                }
                """)
            )
        )
        @RequestBody @Valid MfaSetupCompleteRequest request,
        HttpServletRequest httpRequest) {

        UUID tenantId = TenantContext.getTenantId();
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        
        if (tenantId == null || auth == null) {
            return ResponseEntity.badRequest().body(Map.of("error", "Missing authentication context"));
        }

        try {
            String email = auth.getName();
            UUID userId = getUserIdByEmail(email);
            
            String deviceFingerprint = request.trustDevice ? generateDeviceFingerprint(httpRequest) : null;
            String ipAddress = getClientIpAddress(httpRequest);
            String userAgent = httpRequest.getHeader("User-Agent");

            log.info("Completing MFA setup for user: {} with code verification", email);

            MfaService.MfaVerificationResult result = mfaService.completeMfaSetup(
                userId, tenantId, request.totpCode, deviceFingerprint, ipAddress, userAgent
            );

            if (!result.isSuccess()) {
                return ResponseEntity.badRequest().body(Map.of(
                    "success", false,
                    "message", result.getMessage()
                ));
            }

            Map<String, Object> response = new HashMap<>();
            response.put("success", true);
            response.put("message", result.getMessage());
            response.put("trustedDevice", result.isTrustedDevice());
            response.put("mfaEnabled", true);

            log.info("✅ MFA setup completed successfully for user: {}", email);
            return ResponseEntity.ok(response);

        } catch (Exception e) {
            log.error("❌ Failed to complete MFA setup for user {}: {}", auth.getName(), e.getMessage(), e);
            return ResponseEntity.internalServerError().body(
                Map.of("error", "Failed to complete MFA setup", "message", e.getMessage())
            );
        }
    }

    // ==========================================================================
    // MFA VERIFICATION ENDPOINTS
    // ==========================================================================

    @PostMapping("/verify")
    @Operation(
        summary = "Verify MFA code",
        description = """
        Verifies a TOTP code or backup code for authentication.
        
        Supports:
        - 6-digit TOTP codes from authenticator apps
        - 8-character backup recovery codes
        - Trusted device detection for MFA bypass
        - Rate limiting and account lockout protection
        """
    )
    @ApiResponses({
        @ApiResponse(
            responseCode = "200",
            description = "MFA verification result",
            content = @Content(
                mediaType = "application/json",
                examples = {
                    @ExampleObject(
                        name = "Successful TOTP verification",
                        value = """
                        {
                          "success": true,
                          "message": "TOTP verified successfully",
                          "trustedDevice": false,
                          "method": "TOTP"
                        }
                        """
                    ),
                    @ExampleObject(
                        name = "Trusted device bypass",
                        value = """
                        {
                          "success": true,
                          "message": "Trusted device - MFA bypassed",
                          "trustedDevice": true,
                          "method": "TRUSTED_DEVICE"
                        }
                        """
                    ),
                    @ExampleObject(
                        name = "Failed verification",
                        value = """
                        {
                          "success": false,
                          "message": "Invalid authentication code",
                          "attemptsRemaining": 3
                        }
                        """
                    )
                }
            )
        ),
        @ApiResponse(responseCode = "400", description = "Invalid request or MFA not configured"),
        @ApiResponse(responseCode = "429", description = "Too many failed attempts - account locked")
    })
    public ResponseEntity<?> verifyMfaCode(
        @io.swagger.v3.oas.annotations.parameters.RequestBody(
            description = "MFA verification request",
            content = @Content(
                mediaType = "application/json",
                examples = @ExampleObject(value = """
                {
                  "code": "123456",
                  "trustDevice": false,
                  "deviceName": "Chrome on Windows"
                }
                """)
            )
        )
        @RequestBody @Valid MfaVerificationRequest request,
        HttpServletRequest httpRequest) {

        UUID tenantId = TenantContext.getTenantId();
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        
        if (tenantId == null || auth == null) {
            return ResponseEntity.badRequest().body(Map.of("error", "Missing authentication context"));
        }

        try {
            String email = auth.getName();
            UUID userId = getUserIdByEmail(email);
            
            String deviceFingerprint = generateDeviceFingerprint(httpRequest);
            String ipAddress = getClientIpAddress(httpRequest);
            String userAgent = httpRequest.getHeader("User-Agent");

            log.info("Verifying MFA code for user: {} from IP: {}", email, ipAddress);

            MfaService.MfaVerificationResult result = mfaService.verifyMfaCode(
                userId, tenantId, request.code, deviceFingerprint, ipAddress, userAgent
            );

            Map<String, Object> response = new HashMap<>();
            response.put("success", result.isSuccess());
            response.put("message", result.getMessage());
            response.put("trustedDevice", result.isTrustedDevice());

            if (result.isSuccess()) {
                response.put("method", result.isTrustedDevice() ? "TRUSTED_DEVICE" : 
                           (request.code.length() == 6 ? "TOTP" : "BACKUP_CODE"));
                
                // Optionally trust this device for future logins
                if (request.trustDevice && !result.isTrustedDevice()) {
                    try {
                        UUID deviceId = mfaService.trustDevice(userId, tenantId, deviceFingerprint, 
                                                             request.deviceName, ipAddress, userAgent);
                        response.put("deviceTrusted", true);
                        response.put("deviceId", deviceId.toString());
                    } catch (Exception e) {
                        log.warn("Failed to trust device for user {}: {}", email, e.getMessage());
                    }
                }
                
                log.info("✅ MFA verification successful for user: {}", email);
            } else {
                log.warn("❌ MFA verification failed for user: {} - {}", email, result.getMessage());
            }

            return ResponseEntity.ok(response);

        } catch (Exception e) {
            log.error("❌ MFA verification error for user {}: {}", auth.getName(), e.getMessage(), e);
            return ResponseEntity.internalServerError().body(
                Map.of("error", "MFA verification failed", "message", e.getMessage())
            );
        }
    }

    // ==========================================================================
    // MFA MANAGEMENT ENDPOINTS
    // ==========================================================================

    @GetMapping("/status")
    @Operation(
        summary = "Get MFA status",
        description = "Returns the current MFA configuration and status for the authenticated user"
    )
    @ApiResponse(
        responseCode = "200",
        description = "MFA status retrieved successfully",
        content = @Content(
            mediaType = "application/json",
            examples = @ExampleObject(value = """
            {
              "isSetup": true,
              "isEnabled": true,
              "status": "ENABLED",
              "backupCodesRemaining": 8,
              "lastUsedAt": "2024-09-01T10:30:00Z",
              "trustedDevicesCount": 2,
              "trustedDevices": [
                {
                  "id": "device-uuid",
                  "deviceName": "My Laptop",
                  "lastSeenAt": "2024-09-01T10:30:00Z",
                  "createdAt": "2024-08-15T09:00:00Z"
                }
              ]
            }
            """)
        )
    )
    public ResponseEntity<?> getMfaStatus() {
        UUID tenantId = TenantContext.getTenantId();
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        
        if (tenantId == null || auth == null) {
            return ResponseEntity.badRequest().body(Map.of("error", "Missing authentication context"));
        }

        try {
            String email = auth.getName();
            UUID userId = getUserIdByEmail(email);

            MfaService.MfaStatusResult status = mfaService.getMfaStatus(userId, tenantId);

            Map<String, Object> response = new HashMap<>();
            response.put("isSetup", status.isSetup());
            response.put("isEnabled", status.isEnabled());
            response.put("status", status.getStatus().name());
            response.put("backupCodesRemaining", status.getBackupCodesRemaining());
            response.put("lastUsedAt", status.getLastUsedAt());
            response.put("trustedDevicesCount", status.getTrustedDevices().size());
            response.put("trustedDevices", status.getTrustedDevices().stream()
                .map(device -> Map.of(
                    "id", device.getId().toString(),
                    "deviceName", device.getDeviceName() != null ? device.getDeviceName() : "Unknown Device",
                    "lastSeenAt", device.getLastSeenAt(),
                    "createdAt", device.getCreatedAt(),
                    "expiresAt", device.getExpiresAt()
                ))
                .toList());

            return ResponseEntity.ok(response);

        } catch (Exception e) {
            log.error("❌ Failed to get MFA status for user {}: {}", auth.getName(), e.getMessage(), e);
            return ResponseEntity.internalServerError().body(
                Map.of("error", "Failed to get MFA status", "message", e.getMessage())
            );
        }
    }

    @PostMapping("/backup-codes/regenerate")
    @Operation(
        summary = "Regenerate backup codes",
        description = """
        Generates new backup recovery codes for the user. 
        This invalidates all previous backup codes.
        
        ⚠️ **Important**: Save these codes securely - they won't be shown again!
        """
    )
    @ApiResponse(
        responseCode = "200",
        description = "New backup codes generated",
        content = @Content(
            mediaType = "application/json",
            examples = @ExampleObject(value = """
            {
              "backupCodes": ["ABCD1234", "EFGH5678", "IJKL9012", "..."],
              "message": "New backup codes generated. Save them securely!",
              "generatedAt": "2024-09-01T10:30:00Z"
            }
            """)
        )
    )
    public ResponseEntity<?> regenerateBackupCodes() {
        UUID tenantId = TenantContext.getTenantId();
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        
        if (tenantId == null || auth == null) {
            return ResponseEntity.badRequest().body(Map.of("error", "Missing authentication context"));
        }

        try {
            String email = auth.getName();
            UUID userId = getUserIdByEmail(email);

            log.info("Regenerating backup codes for user: {}", email);

            List<String> newCodes = mfaService.regenerateBackupCodes(userId, tenantId);

            Map<String, Object> response = new HashMap<>();
            response.put("backupCodes", newCodes);
            response.put("message", "New backup codes generated. Save them securely - they won't be shown again!");
            response.put("generatedAt", OffsetDateTime.now());
            response.put("codesCount", newCodes.size());

            log.info("✅ Backup codes regenerated for user: {}", email);
            return ResponseEntity.ok(response);

        } catch (Exception e) {
            log.error("❌ Failed to regenerate backup codes for user {}: {}", auth.getName(), e.getMessage(), e);
            return ResponseEntity.internalServerError().body(
                Map.of("error", "Failed to regenerate backup codes", "message", e.getMessage())
            );
        }
    }

    @PostMapping("/disable")
    @Operation(
        summary = "Disable MFA",
        description = """
        Disables MFA for the authenticated user.
        
        ⚠️ **Security Warning**: This reduces account security.
        All trusted devices will be revoked.
        """
    )
    @ApiResponse(
        responseCode = "200",
        description = "MFA disabled successfully",
        content = @Content(
            mediaType = "application/json",
            examples = @ExampleObject(value = """
            {
              "success": true,
              "message": "MFA has been disabled for your account",
              "trustedDevicesRevoked": 3
            }
            """)
        )
    )
    public ResponseEntity<?> disableMfa(
        @io.swagger.v3.oas.annotations.parameters.RequestBody(
            description = "MFA disable confirmation",
            content = @Content(
                mediaType = "application/json",
                examples = @ExampleObject(value = """
                {
                  "confirmDisable": true,
                  "reason": "No longer needed"
                }
                """)
            )
        )
        @RequestBody @Valid MfaDisableRequest request) {

        if (!request.confirmDisable) {
            return ResponseEntity.badRequest().body(Map.of("error", "Must confirm MFA disable"));
        }

        UUID tenantId = TenantContext.getTenantId();
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        
        if (tenantId == null || auth == null) {
            return ResponseEntity.badRequest().body(Map.of("error", "Missing authentication context"));
        }

        try {
            String email = auth.getName();
            UUID userId = getUserIdByEmail(email);

            log.info("Disabling MFA for user: {} - Reason: {}", email, request.reason);

            mfaService.disableMfa(userId, tenantId);

            Map<String, Object> response = new HashMap<>();
            response.put("success", true);
            response.put("message", "MFA has been disabled for your account");
            response.put("disabledAt", OffsetDateTime.now());

            log.info("✅ MFA disabled for user: {}", email);
            return ResponseEntity.ok(response);

        } catch (Exception e) {
            log.error("❌ Failed to disable MFA for user {}: {}", auth.getName(), e.getMessage(), e);
            return ResponseEntity.internalServerError().body(
                Map.of("error", "Failed to disable MFA", "message", e.getMessage())
            );
        }
    }

    // ==========================================================================
    // TRUSTED DEVICE MANAGEMENT
    // ==========================================================================

    @PostMapping("/devices/{deviceId}/revoke")
    @Operation(
        summary = "Revoke trusted device",
        description = "Revokes a trusted device, requiring MFA for future logins from that device"
    )
    public ResponseEntity<?> revokeTrustedDevice(@PathVariable UUID deviceId) {
        UUID tenantId = TenantContext.getTenantId();
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        
        if (tenantId == null || auth == null) {
            return ResponseEntity.badRequest().body(Map.of("error", "Missing authentication context"));
        }

        try {
            String email = auth.getName();
            UUID userId = getUserIdByEmail(email);

            log.info("Revoking trusted device {} for user: {}", deviceId, email);

            mfaService.revokeTrustedDevice(userId, deviceId, userId);

            Map<String, Object> response = new HashMap<>();
            response.put("success", true);
            response.put("message", "Trusted device revoked successfully");
            response.put("deviceId", deviceId.toString());
            response.put("revokedAt", OffsetDateTime.now());

            log.info("✅ Trusted device revoked: {} for user: {}", deviceId, email);
            return ResponseEntity.ok(response);

        } catch (Exception e) {
            log.error("❌ Failed to revoke trusted device {} for user {}: {}", deviceId, auth.getName(), e.getMessage(), e);
            return ResponseEntity.internalServerError().body(
                Map.of("error", "Failed to revoke trusted device", "message", e.getMessage())
            );
        }
    }

    // ==========================================================================
    // PRIVATE HELPER METHODS
    // ==========================================================================

    private UUID getUserIdByEmail(String email) {
        UserEntity user = userRepository.findByEmail(email.toLowerCase())
                .orElseThrow(() -> new IllegalStateException("User not found: " + email));
        return user.getId();
    }

    private String generateDeviceFingerprint(HttpServletRequest request) {
        String userAgent = request.getHeader("User-Agent");
        String acceptLanguage = request.getHeader("Accept-Language");
        String acceptEncoding = request.getHeader("Accept-Encoding");
        
        String fingerprint = String.format("%s|%s|%s", 
            userAgent != null ? userAgent : "",
            acceptLanguage != null ? acceptLanguage : "",
            acceptEncoding != null ? acceptEncoding : ""
        );
        
        return Integer.toHexString(fingerprint.hashCode());
    }

    private String getClientIpAddress(HttpServletRequest request) {
        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.isEmpty()) {
            return xForwardedFor.split(",")[0].trim();
        }
        
        String xRealIp = request.getHeader("X-Real-IP");
        if (xRealIp != null && !xRealIp.isEmpty()) {
            return xRealIp;
        }
        
        return request.getRemoteAddr();
    }

    // ==========================================================================
    // REQUEST/RESPONSE DTOs
    // ==========================================================================

    @Schema(description = "MFA setup completion request")
    public static class MfaSetupCompleteRequest {
        @Schema(description = "6-digit TOTP code from authenticator app", example = "123456")
        @NotBlank(message = "TOTP code is required")
        @Pattern(regexp = "^[0-9]{6}$", message = "TOTP code must be 6 digits")
        public String totpCode;

        @Schema(description = "Whether to trust this device for future logins", example = "true")
        public boolean trustDevice = false;

        @Schema(description = "Friendly name for the trusted device", example = "My Laptop")
        @Size(max = 100, message = "Device name too long")
        public String deviceName;
    }

    @Schema(description = "MFA verification request")
    public static class MfaVerificationRequest {
        @Schema(description = "6-digit TOTP code or 8-character backup code", example = "123456")
        @NotBlank(message = "Authentication code is required")
        @Pattern(regexp = "^([0-9]{6}|[A-Z0-9]{8})$", message = "Invalid code format")
        public String code;

        @Schema(description = "Whether to trust this device for future logins", example = "false")
        public boolean trustDevice = false;

        @Schema(description = "Friendly name for the trusted device", example = "Chrome on Windows")
        @Size(max = 100, message = "Device name too long")
        public String deviceName;
    }

    @Schema(description = "MFA disable request")
    public static class MfaDisableRequest {
        @Schema(description = "Confirmation that user wants to disable MFA", example = "true")
        public boolean confirmDisable;

        @Schema(description = "Optional reason for disabling MFA", example = "No longer needed")
        @Size(max = 200, message = "Reason too long")
        public String reason;
    }
}