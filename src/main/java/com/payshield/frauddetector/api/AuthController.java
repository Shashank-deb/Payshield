// ==============================================================================
// Step 11: Enhanced AuthController with OpenAPI Documentation
// Update: src/main/java/com/payshield/frauddetector/api/AuthController.java
// ==============================================================================

package com.payshield.frauddetector.api;

import com.payshield.frauddetector.config.JwtService;
import com.payshield.frauddetector.infrastructure.jpa.SpringUserRepository;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.ExampleObject;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/auth")
@Tag(name = "Authentication", description = "User authentication and token management")
public class AuthController {

    private final SpringUserRepository users;
    private final PasswordEncoder encoder;
    private final JwtService jwt;

    public AuthController(SpringUserRepository users, PasswordEncoder encoder, JwtService jwt) {
        this.users = users; this.encoder = encoder; this.jwt = jwt;
    }

    @PostMapping("/login")
    @Operation(
            summary = "Authenticate user and obtain JWT token",
            description = "Login with email and password to receive a Bearer token for API access"
    )
    @ApiResponses({
            @ApiResponse(
                    responseCode = "200",
                    description = "Authentication successful",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = LoginResponse.class),
                            examples = @ExampleObject(value = """
                    {
                        "accessToken": "eyJhbGciOiJIUzI1NiJ9...",
                        "tokenType": "Bearer",
                        "expiresInSeconds": 3600,
                        "user": {
                            "email": "admin@yourcompany.com",
                            "roles": ["ADMIN", "ANALYST", "APPROVER"],
                            "tenantId": "00000000-0000-0000-0000-000000000001"
                        }
                    }
                    """)
                    )
            ),
            @ApiResponse(
                    responseCode = "401",
                    description = "Invalid credentials",
                    content = @Content(
                            mediaType = "application/json",
                            examples = @ExampleObject(value = """
                    {
                        "error": "Invalid credentials"
                    }
                    """)
                    )
            )
    })
    public ResponseEntity<?> login(
            @io.swagger.v3.oas.annotations.parameters.RequestBody(
                    description = "User login credentials",
                    required = true,
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = LoginRequest.class),
                            examples = @ExampleObject(value = """
                        {
                            "email": "admin@yourcompany.com",
                            "password": "your-password"
                        }
                        """)
                    )
            )
            @RequestBody @Valid LoginRequest req) {

        var user = users.findByEmail(req.email().toLowerCase()).orElse(null);
        if (user == null || !encoder.matches(req.password(), user.getPasswordHash())) {
            return ResponseEntity.status(401).body(Map.of("error","Invalid credentials"));
        }
        var token = jwt.generateToken(user.getEmail(), user.getTenantId(), user.getRoles());
        return ResponseEntity.ok(Map.of(
                "accessToken", token,
                "tokenType", "Bearer",
                "expiresInSeconds", 3600,
                "user", Map.of(
                        "email", user.getEmail(),
                        "roles", user.getRoles(),
                        "tenantId", user.getTenantId().toString()
                )
        ));
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
                        "tenantId": "00000000-0000-0000-0000-000000000001"
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
                            "message", "Send 'Authorization: Bearer <token>'"));
        }

        String token = authHeader.substring(7).trim();

        var subjectOpt = jwt.getSubject(token);
        if (subjectOpt.isEmpty()) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("error", "Unauthorized", "message", "Invalid or expired token"));
        }

        var roles   = jwt.getRoles(token);
        var tenant  = jwt.getTenantId(token).orElse(null);

        return ResponseEntity.ok(Map.of(
                "subject",  subjectOpt.get(),
                "roles",    roles,
                "tenantId", tenant
        ));
    }

    // DTOs with OpenAPI documentation
    @Schema(description = "User login request")
    public record LoginRequest(
            @Schema(description = "User email address", example = "admin@yourcompany.com")
            @Email String email,

            @Schema(description = "User password", example = "secure-password")
            @NotBlank String password
    ) {}

    @Schema(description = "Successful login response")
    public record LoginResponse(
            @Schema(description = "JWT access token")
            String accessToken,

            @Schema(description = "Token type", example = "Bearer")
            String tokenType,

            @Schema(description = "Token expiration time in seconds", example = "3600")
            int expiresInSeconds,

            @Schema(description = "User information")
            UserInfo user
    ) {}

    @Schema(description = "User information")
    public record UserInfo(
            @Schema(description = "User email", example = "admin@yourcompany.com")
            String email,

            @Schema(description = "User roles", example = "[\"ADMIN\", \"ANALYST\"]")
            java.util.Set<String> roles,

            @Schema(description = "Tenant ID", example = "00000000-0000-0000-0000-000000000001")
            String tenantId
    ) {}
}