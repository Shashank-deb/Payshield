package com.payshield.frauddetector.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.time.Instant;
import java.util.*;

@Component
public class JwtService {

    private final Key key;
    private final long ttlSeconds;

    public JwtService(
            @Value("${security.jwt.secret}") String secret,
            @Value("${security.jwt.ttl-seconds:3600}") long ttlSeconds) {
        this.key = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
        this.ttlSeconds = ttlSeconds;
    }

    /* ------------------------ token creation ------------------------ */

    /** Matches AuthController expectation: generateToken(email, tenantId, roles). */
    public String generateToken(String subjectEmail, UUID tenantId, Set<String> roles) {
        Instant now = Instant.now();
        Date iat = Date.from(now);
        Date exp = Date.from(now.plusSeconds(ttlSeconds));

        // Use "tenantId" as primary claim; some older tokens may have used "tid".
        return Jwts.builder()
                .setSubject(subjectEmail)
                .setIssuedAt(iat)
                .setExpiration(exp)
                .claim("roles", roles == null ? List.of() : roles)
                .claim("tenantId", tenantId == null ? null : tenantId.toString())
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();
    }

    /* ------------------------ token parsing ------------------------ */

    public Jws<Claims> parse(String token) {
        return Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token);
    }

    public Optional<String> getSubject(String token) {
        try {
            return Optional.ofNullable(parse(token).getBody().getSubject());
        } catch (Exception e) {
            return Optional.empty();
        }
    }

    @SuppressWarnings("unchecked")
    public Set<String> getRoles(String token) {
        try {
            Object rolesObj = parse(token).getBody().get("roles");
            if (rolesObj instanceof Collection<?> col) {
                Set<String> out = new HashSet<>();
                for (Object o : col) out.add(String.valueOf(o));
                return out;
            }
            return Set.of();
        } catch (Exception e) {
            return Set.of();
        }
    }

    /** Accept both "tenantId" and legacy "tid" claim names. */
    public Optional<String> getTenantId(String token) {
        try {
            Claims c = parse(token).getBody();
            Object v = c.get("tenantId");
            if (v == null) v = c.get("tid");
            return v == null ? Optional.empty() : Optional.of(String.valueOf(v));
        } catch (Exception e) {
            return Optional.empty();
        }
    }
}
