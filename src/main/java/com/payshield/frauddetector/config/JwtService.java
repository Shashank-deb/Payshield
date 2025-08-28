package com.payshield.frauddetector.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.time.Instant;
import java.util.*;

@Component
public class JwtService {

    private static final Logger log = LoggerFactory.getLogger(JwtService.class);

    private final Key key;
    private final long ttlSeconds;

    public JwtService(
            @Value("${security.jwt.secret}") String secret,
            @Value("${security.jwt.ttl-seconds:3600}") long ttlSeconds) {
        this.key = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
        this.ttlSeconds = ttlSeconds;
        log.info("JWT service initialized with TTL: {} seconds", ttlSeconds);
    }

    /* ------------------------ token creation ------------------------ */

    /** Matches AuthController expectation: generateToken(email, tenantId, roles). */
    public String generateToken(String subjectEmail, UUID tenantId, Set<String> roles) {
        Instant now = Instant.now();
        Date iat = Date.from(now);
        Date exp = Date.from(now.plusSeconds(ttlSeconds));

        log.debug("Generating JWT token for user: {}, tenant: {}, roles: {}", subjectEmail, tenantId, roles);

        // Use "tenantId" as primary claim; some older tokens may have used "tid".
        String token = Jwts.builder()
                .setSubject(subjectEmail)
                .setIssuedAt(iat)
                .setExpiration(exp)
                .claim("roles", roles == null ? List.of() : new ArrayList<>(roles))
                .claim("tenantId", tenantId == null ? null : tenantId.toString())
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();

        log.debug("Generated JWT token successfully for user: {}", subjectEmail);
        return token;
    }

    /* ------------------------ token parsing ------------------------ */

    public Jws<Claims> parse(String token) {
        try {
            return Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token);
        } catch (Exception e) {
            log.debug("Failed to parse JWT token: {}", e.getMessage());
            throw e;
        }
    }

    public Optional<String> getSubject(String token) {
        try {
            Claims claims = parse(token).getBody();
            String subject = claims.getSubject();
            log.debug("Extracted subject from token: {}", subject);
            return Optional.ofNullable(subject);
        } catch (Exception e) {
            log.warn("Failed to extract subject from token: {}", e.getMessage());
            return Optional.empty();
        }
    }

    @SuppressWarnings("unchecked")
    public Set<String> getRoles(String token) {
        try {
            Claims claims = parse(token).getBody();
            Object rolesObj = claims.get("roles");

            if (rolesObj instanceof Collection<?> col) {
                Set<String> roles = new HashSet<>();
                for (Object o : col) {
                    roles.add(String.valueOf(o));
                }
                log.debug("Extracted roles from token: {}", roles);
                return roles;
            }

            log.debug("No roles found in token");
            return Set.of();
        } catch (Exception e) {
            log.warn("Failed to extract roles from token: {}", e.getMessage());
            return Set.of();
        }
    }

    /** Accept both "tenantId" and legacy "tid" claim names. */
    public Optional<String> getTenantId(String token) {
        try {
            Claims claims = parse(token).getBody();
            Object tenantId = claims.get("tenantId");
            if (tenantId == null) {
                tenantId = claims.get("tid"); // legacy support
            }

            String result = tenantId == null ? null : String.valueOf(tenantId);
            log.debug("Extracted tenant ID from token: {}", result);
            return Optional.ofNullable(result);
        } catch (Exception e) {
            log.warn("Failed to extract tenant ID from token: {}", e.getMessage());
            return Optional.empty();
        }
    }

    /** Utility method to check if token is expired */
    public boolean isTokenExpired(String token) {
        try {
            Claims claims = parse(token).getBody();
            return claims.getExpiration().before(new Date());
        } catch (Exception e) {
            log.debug("Token validation failed: {}", e.getMessage());
            return true;
        }
    }
}