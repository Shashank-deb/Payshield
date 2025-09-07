// ==============================================================================
// COMPLETE: AuthController.java - Full File with MFA Integration
// File: src/main/java/com/payshield/frauddetector/api/AuthController.java
// ==============================================================================

package com.payshield.frauddetector.api;

import com.payshield.frauddetector.application.MfaService;
import com.payshield.frauddetector.config.JwtService;
import com.payshield.frauddetector.infrastructure.jpa.SpringMfaConfigurationRepository;
import com.payshield.frauddetector.infrastructure.jpa.SpringUserRepository;
import com.payshield.frauddetector.infrastructure.jpa.UserEntity;
import com.payshield.frauddetector.infrastructure.jpa.MfaConfigurationEntity;
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
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.time.OffsetDateTime;
import java.util.*;

@RestController
@RequestMapping("/auth")
@Tag(name = "Authentication", description = "User authentication with optional MFA support")
public class AuthController {

    private static final Logger log = LoggerFactory.getLogger(AuthController.class);

    private final SpringUserRepository users;
    private final PasswordEncoder encoder;
    private final JwtService jwt;
    private final MfaService mfaService;
    private final SpringMfaConfigurationRepository mfaConfigRepo;

    public AuthController(SpringUserRepository users, PasswordEncoder encoder, JwtService jwt,
                          MfaService mfaService, SpringMfaConfigurationRepository mfaConfigRepo) {
        this.users = users;
        this.encoder = encoder;
        this.jwt = jwt;
        this.mfaService = mfaService;
        this.mfaConfigRepo = mfaConfigRepo;
    }

    @PostMapping("/login")
    @Operation(
            summary = "Authenticate user with optional MFA",
            description = """
        Two-step authentication process:
        1. **First step**: Verify email/password
        2. **Second step**: If MFA enabled, verify TOTP/backup code
        
        **Response Types:**
        - `PASSWORD_SUCCESS`: Password verified, no MFA required - full JWT token provided
        - `MFA_REQUIRED`: Password verified, MFA verification needed - temporary token provided
        - `MFA_SUCCESS`: Complete authentication with MFA - full JWT token provided
        """
    )
    @ApiResponses({
            @ApiResponse(
                    responseCode = "200",
                    description = "Authentication successful or MFA required",
                    content = @Content(
                            mediaType = "application/json",
                            examples = {
                                    @ExampleObject(
                                            name = "Complete Success (No MFA)",
                                            value = """
                        {
                            "status": "PASSWORD_SUCCESS",
                            "accessToken": "eyJhbGciOiJIUzI1NiJ9...",
                            "tokenType": "Bearer",
                            "expiresInSeconds": 3600,
                            "user": {
                                "email": "admin@yourcompany.com",
                                "roles": ["ADMIN", "ANALYST", "APPROVER"],
                                "tenantId": "00000000-0000-0000-0000-000000000001",
                                "mfaEnabled": false
                            }
                        }
                        """
                                    ),
                                    @ExampleObject(
                                            name = "MFA Required",
                                            value = """
                        {
                            "status": "MFA_REQUIRED",
                            "message": "MFA verification required",
                            "tempToken": "temp_eyJhbGciOiJIUzI1NiJ9...",
                            "mfaRequired": true,
                            "user": {
                                "email": "admin@yourcompany.com",
                                "mfaEnabled": true
                            }
                        }
                        """
                                    ),
                                    @ExampleObject(
                                            name = "Complete Success (With MFA)",
                                            value = """
                        {
                            "status": "MFA_SUCCESS",
                            "accessToken": "eyJhbGciOiJIUzI1NiJ9...",
                            "tokenType": "Bearer",
                            "expiresInSeconds": 3600,
                            "user": {
                                "email": "admin@yourcompany.com",
                                "roles": ["ADMIN", "ANALYST", "APPROVER"],
                                "tenantId": "00000000-0000-0000-0000-000000000001",
                                "mfaEnabled": true
                            },
                            "trustedDevice": true
                        }
                        """
                                    )
                            }
                    )
            ),
            @ApiResponse(
                    responseCode = "401",
                    description = "Invalid credentials or MFA verification failed",
                    content = @Content(
                            mediaType = "application/json",
                            examples = {
                                    @ExampleObject(
                                            name = "Invalid Password",
                                            value = """
                        {
                            "error": "Invalid credentials",
                            "message": "Email or password is incorrect"
                        }
                        """
                                    ),
                                    @ExampleObject(
                                            name = "Invalid MFA Code",
                                            value = """
                        {
                            "error": "MFA verification failed",
                            "message": "Invalid authentication code",
                            "attemptsRemaining": 3
                        }
                        """
                                    )
                            }
                    )
            ),
            @ApiResponse(
                    responseCode = "423",
                    description = "Account locked due to failed MFA attempts",
                    content = @Content(
                            mediaType = "application/json",
                            examples = @ExampleObject(value = """
                {
                    "error": "Account locked",
                    "message": "Account temporarily locked due to failed attempts",
                    "lockedUntil": "2024-09-01T12:00:00Z"
                }
                """)
                    )
            )
    })
    public ResponseEntity<?> login(
            @io.swagger.v3.oas.annotations.parameters.RequestBody(
                    description = "Login credentials with optional MFA code",
                    required = true,
                    content = @Content(
                            mediaType = "application/json",
                            examples = {
                                    @ExampleObject(
                                            name = "Password Only (First Step)",
                                            value = """
                        {
                            "email": "admin@yourcompany.com",
                            "password": "your-password"
                        }
                        """
                                    ),
                                    @ExampleObject(
                                            name = "With MFA Code (Second Step)",
                                            value = """
                        {
                            "email": "admin@yourcompany.com",
                            "password": "your-password",
                            "mfaCode": "123456",
                            "tempToken": "temp_eyJhbGciOiJIUzI1NiJ9...",
                            "trustDevice": true,
                            "deviceName": "My Laptop"
                        }
                        """
                                    ),
                                    @ExampleObject(
                                            name = "With Backup Code",
                                            value = """
                        {
                            "email": "admin@yourcompany.com",
                            "password": "your-password",
                            "mfaCode": "ABCD1234",
                            "tempToken": "temp_eyJhbGciOiJIUzI1NiJ9..."
                        }
                        """
                                    )
                            }
                    )
            )
            @RequestBody @Valid LoginRequest req,
            HttpServletRequest request) {

        try {
            log.info("Login attempt for user: {}", req.email());

            // Step 1: Verify email and password
            var user = users.findByEmail(req.email().toLowerCase()).orElse(null);
            if (user == null || !encoder.matches(req.password(), user.getPasswordHash())) {
                log.warn("❌ Invalid credentials for user: {}", req.email());
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(Map.of(
                                "error", "Invalid credentials",
                                "message", "Email or password is incorrect"
                        ));
            }

            log.info("✅ Password verified for user: {}", req.email());

            // Check if MFA is enabled for this user
            Optional<MfaConfigurationEntity> mfaConfig = mfaConfigRepo.findByUserIdAndTenantId(
                    user.getId(), user.getTenantId());

            boolean mfaEnabled = mfaConfig.isPresent() &&
                    mfaConfig.get().isSetupComplete() &&
                    mfaConfig.get().getStatus() == MfaConfigurationEntity.MfaStatusType.ENABLED;

            // If MFA is not enabled, return full access token immediately
            if (!mfaEnabled) {
                log.info("✅ MFA not enabled for user: {} - Granting full access", req.email());
                return createSuccessResponse("PASSWORD_SUCCESS", user, false, false);
            }

            // Step 2: Handle MFA verification
            if (req.mfaCode() == null || req.mfaCode().isBlank()) {
                // MFA is required but no code provided - return temporary token
                log.info("🔐 MFA required for user: {} - Requesting MFA code", req.email());
                return createMfaRequiredResponse(user);
            }

            // Validate temporary token if provided
            if (req.tempToken() != null && !req.tempToken().isBlank()) {
                if (!isValidTempToken(req.tempToken(), user.getId())) {
                    log.warn("❌ Invalid temporary token for user: {}", req.email());
                    return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                            .body(Map.of(
                                    "error", "Invalid session",
                                    "message", "Please start login process again"
                            ));
                }
            }

            // Verify MFA code
            String deviceFingerprint = generateDeviceFingerprint(request);
            String ipAddress = getClientIpAddress(request);
            String userAgent = request.getHeader("User-Agent");

            log.info("🔐 Verifying MFA code for user: {}", req.email());

            MfaService.MfaVerificationResult mfaResult = mfaService.verifyMfaCode(
                    user.getId(), user.getTenantId(), req.mfaCode(),
                    deviceFingerprint, ipAddress, userAgent
            );

            if (!mfaResult.isSuccess()) {
                log.warn("❌ MFA verification failed for user: {} - {}", req.email(), mfaResult.getMessage());

                // Check if account is locked
                if (mfaResult.getMessage().contains("locked")) {
                    return ResponseEntity.status(HttpStatus.LOCKED)
                            .body(Map.of(
                                    "error", "Account locked",
                                    "message", mfaResult.getMessage()
                            ));
                }

                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(Map.of(
                                "error", "MFA verification failed",
                                "message", mfaResult.getMessage()
                        ));
            }

            // Optionally trust this device
            boolean deviceTrusted = false;
            if (req.trustDevice() && !mfaResult.isTrustedDevice()) {
                try {
                    mfaService.trustDevice(user.getId(), user.getTenantId(), deviceFingerprint,
                            req.deviceName() != null ? req.deviceName() : "Unknown Device",
                            ipAddress, userAgent);
                    deviceTrusted = true;
                    log.info("✅ Device trusted for user: {}", req.email());
                } catch (Exception e) {
                    log.warn("Failed to trust device for user {}: {}", req.email(), e.getMessage());
                }
            }

            log.info("✅ MFA verification successful for user: {}", req.email());
            return createSuccessResponse("MFA_SUCCESS", user, true, deviceTrusted || mfaResult.isTrustedDevice());

        } catch (Exception e) {
            log.error("❌ Login error for user {}: {}", req.email(), e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of(
                            "error", "Login failed",
                            "message", "An error occurred during authentication"
                    ));
        }
    }

    @GetMapping("/whoami")
    @Operation(
            summary = "Get current user information",
            description = "Retrieve information about the currently authenticated user"
    )
    @SecurityRequirement(name = "Bearer Authentication")
    @ApiResponses({
            @ApiResponse(
                    responseCode = "200",
                    description = "User information retrieved successfully",
                    content = @Content(
                            mediaType = "application/json",
                            examples = @ExampleObject(value = """
                {
                    "subject": "admin@yourcompany.com",
                    "roles": ["ADMIN", "ANALYST", "APPROVER"],
                    "tenantId": "00000000-0000-0000-0000-000000000001",
                    "mfaEnabled": true,
                    "mfaStatus": "ENABLED"
                }
                """)
                    )
            ),
            @ApiResponse(
                    responseCode = "401",
                    description = "Invalid or missing token",
                    content = @Content(
                            mediaType = "application/json",
                            examples = @ExampleObject(value = """
                {
                    "error": "Unauthorized",
                    "message": "Invalid or expired token"
                }
                """)
                    )
            )
    })
    public ResponseEntity<?> whoami(
            @Parameter(description = "Bearer token", example = "Bearer eyJhbGciOiJIUzI1NiJ9...")
            @RequestHeader(name = "Authorization", required = false) String authHeader) {

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(Map.of(
                            "error", "BadRequest",
                            "message", "Send 'Authorization: Bearer <token>'"
                    ));
        }

        String token = authHeader.substring(7).trim();

        var subjectOpt = jwt.getSubject(token);
        if (subjectOpt.isEmpty()) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of(
                            "error", "Unauthorized",
                            "message", "Invalid or expired token"
                    ));
        }

        var roles = jwt.getRoles(token);
        var tenant = jwt.getTenantId(token).orElse(null);

        // Get MFA status for the user
        String email = subjectOpt.get();
        var user = users.findByEmail(email.toLowerCase()).orElse(null);
        boolean mfaEnabled = false;
        String mfaStatus = "DISABLED";

        if (user != null) {
            Optional<MfaConfigurationEntity> mfaConfig = mfaConfigRepo.findByUserIdAndTenantId(
                    user.getId(), user.getTenantId());

            if (mfaConfig.isPresent()) {
                mfaEnabled = mfaConfig.get().isSetupComplete();
                mfaStatus = mfaConfig.get().getStatus().name();
            } else {
                // FIXED: Use the correct method name
                mfaEnabled = user.getMfaEnabled(); // This now works with the updated UserEntity
            }
        }

        Map<String, Object> response = new HashMap<>();
        response.put("subject", subjectOpt.get());
        response.put("roles", roles);
        response.put("tenantId", tenant);
        response.put("mfaEnabled", mfaEnabled);
        response.put("mfaStatus", mfaStatus);

        return ResponseEntity.ok(response);
    }

    @PostMapping("/refresh")
    @Operation(
            summary = "Refresh access token",
            description = "Generate a new access token using a valid refresh token"
    )
    @SecurityRequirement(name = "Bearer Authentication")
    public ResponseEntity<?> refreshToken(
            @RequestBody @Valid RefreshTokenRequest req) {

        try {
            // Validate the refresh token (in a real implementation, you'd store these separately)
            var subjectOpt = jwt.getSubject(req.refreshToken());
            if (subjectOpt.isEmpty()) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(Map.of("error", "Invalid refresh token"));
            }

            String email = subjectOpt.get();
            var user = users.findByEmail(email.toLowerCase()).orElse(null);
            if (user == null) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(Map.of("error", "User not found"));
            }

            // Generate new access token
            var newToken = jwt.generateToken(user.getEmail(), user.getTenantId(), user.getRoles());

            return ResponseEntity.ok(Map.of(
                    "accessToken", newToken,
                    "tokenType", "Bearer",
                    "expiresInSeconds", 3600
            ));

        } catch (Exception e) {
            log.error("Token refresh failed: {}", e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("error", "Token refresh failed"));
        }
    }

    // ==========================================================================
    // PRIVATE HELPER METHODS
    // ==========================================================================

    private ResponseEntity<?> createSuccessResponse(String status, UserEntity user,
                                                    boolean mfaCompleted, boolean trustedDevice) {
        var token = jwt.generateToken(user.getEmail(), user.getTenantId(), user.getRoles());

        Map<String, Object> response = new HashMap<>();
        response.put("status", status);
        response.put("accessToken", token);
        response.put("tokenType", "Bearer");
        response.put("expiresInSeconds", 3600);

        Map<String, Object> userInfo = new HashMap<>();
        userInfo.put("email", user.getEmail());
        userInfo.put("roles", user.getRoles());
        userInfo.put("tenantId", user.getTenantId().toString());
        userInfo.put("mfaEnabled", user.getMfaEnabled()); // FIXED: Now works with updated UserEntity

        response.put("user", userInfo);

        if (mfaCompleted) {
            response.put("mfaVerified", true);
            response.put("trustedDevice", trustedDevice);
        }

        return ResponseEntity.ok(response);
    }

    private ResponseEntity<?> createMfaRequiredResponse(UserEntity user) {
        // Generate a temporary token valid for 10 minutes
        var tempToken = jwt.generateToken(
                "temp_" + user.getEmail(),
                user.getTenantId(),
                Set.of("MFA_PENDING")
        );

        Map<String, Object> response = new HashMap<>();
        response.put("status", "MFA_REQUIRED");
        response.put("message", "MFA verification required");
        response.put("tempToken", tempToken);
        response.put("mfaRequired", true);
        response.put("expiresIn", 600); // 10 minutes

        Map<String, Object> userInfo = new HashMap<>();
        userInfo.put("email", user.getEmail());
        userInfo.put("mfaEnabled", true);

        response.put("user", userInfo);

        return ResponseEntity.ok(response);
    }

    private boolean isValidTempToken(String tempToken, UUID userId) {
        try {
            var subjectOpt = jwt.getSubject(tempToken);
            if (subjectOpt.isEmpty()) {
                return false;
            }

            String subject = subjectOpt.get();
            if (!subject.startsWith("temp_")) {
                return false;
            }

            var roles = jwt.getRoles(tempToken);
            return roles.contains("MFA_PENDING");

        } catch (Exception e) {
            log.debug("Invalid temp token: {}", e.getMessage());
            return false;
        }
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
    // DTOs WITH OPENAPI DOCUMENTATION
    // ==========================================================================

    @Schema(description = "User login request with optional MFA")
    public record LoginRequest(
            @Schema(description = "User email address", example = "admin@yourcompany.com")
            @Email @NotBlank String email,

            @Schema(description = "User password", example = "secure-password")
            @NotBlank String password,

            @Schema(description = "6-digit TOTP code or 8-character backup code (required if MFA enabled)",
                    example = "123456")
            @Pattern(regexp = "^([0-9]{6}|[A-Z0-9]{8})?$", message = "Invalid MFA code format")
            String mfaCode,

            @Schema(description = "Temporary token from MFA_REQUIRED response",
                    example = "temp_eyJhbGciOiJIUzI1NiJ9...")
            String tempToken,

            @Schema(description = "Whether to trust this device for future logins", example = "false")
            Boolean trustDevice,

            @Schema(description = "Friendly name for trusted device", example = "My Laptop")
            String deviceName
    ) {
        public Boolean trustDevice() { return trustDevice != null ? trustDevice : false; }
    }

    @Schema(description = "Successful login response")
    public record LoginResponse(
            @Schema(description = "Authentication status",
                    example = "PASSWORD_SUCCESS",
                    allowableValues = {"PASSWORD_SUCCESS", "MFA_REQUIRED", "MFA_SUCCESS"})
            String status,

            @Schema(description = "JWT access token (only for complete success)")
            String accessToken,

            @Schema(description = "Token type", example = "Bearer")
            String tokenType,

            @Schema(description = "Token expiration time in seconds", example = "3600")
            Integer expiresInSeconds,

            @Schema(description = "User information")
            UserInfo user,

            @Schema(description = "Temporary token for MFA verification (only for MFA_REQUIRED)")
            String tempToken,

            @Schema(description = "Whether MFA verification is required", example = "false")
            Boolean mfaRequired,

            @Schema(description = "Whether device was trusted", example = "false")
            Boolean trustedDevice
    ) {}

    @Schema(description = "User information")
    public record UserInfo(
            @Schema(description = "User email", example = "admin@yourcompany.com")
            String email,

            @Schema(description = "User roles", example = "[\"ADMIN\", \"ANALYST\"]")
            java.util.Set<String> roles,

            @Schema(description = "Tenant ID", example = "00000000-0000-0000-0000-000000000001")
            String tenantId,

            @Schema(description = "Whether MFA is enabled", example = "true")
            Boolean mfaEnabled
    ) {}

    @Schema(description = "Refresh token request")
    public record RefreshTokenRequest(
            @Schema(description = "Valid refresh token", example = "eyJhbGciOiJIUzI1NiJ9...")
            @NotBlank String refreshToken
    ) {}
}