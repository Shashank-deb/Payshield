package com.payshield.frauddetector.api;

import com.payshield.frauddetector.config.JwtService;
import com.payshield.frauddetector.infrastructure.jpa.SpringUserRepository;
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
public class AuthController {

    private final SpringUserRepository users;
    private final PasswordEncoder encoder;
    private final JwtService jwt;

    public AuthController(SpringUserRepository users, PasswordEncoder encoder, JwtService jwt) {
        this.users = users; this.encoder = encoder; this.jwt = jwt;
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody @Valid LoginRequest req) {
        var user = users.findByEmail(req.email().toLowerCase())
                .orElse(null);
        if (user == null || !encoder.matches(req.password(), user.getPasswordHash())) {
            return ResponseEntity.status(401).body(Map.of("error","Invalid credentials"));
        }
        var token = jwt.generateToken(user.getEmail(), user.getTenantId(), user.getRoles());
        return ResponseEntity.ok(Map.of(
                "accessToken", token,
                "tokenType", "Bearer",
                "expiresInSeconds", 3600,
                "user", Map.of("email", user.getEmail(), "roles", user.getRoles(), "tenantId", user.getTenantId().toString())
        ));
    }




    // DTOs
    public record LoginRequest(@Email String email, @NotBlank String password) {}




    @GetMapping("/whoami")
    public ResponseEntity<?> whoami(
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

}
