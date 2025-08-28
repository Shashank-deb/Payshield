package com.payshield.frauddetector.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

public class JwtAuthFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(JwtAuthFilter.class);
    private final JwtService jwt;

    public JwtAuthFilter(JwtService jwt) {
        this.jwt = jwt;
    }

    @Override
    protected boolean shouldNotFilter(@NonNull HttpServletRequest req) {
        String path = req.getRequestURI();
        String method = req.getMethod();

        log.debug("Checking if should filter: {} {}", method, path);

        // Skip OPTIONS requests
        if ("OPTIONS".equalsIgnoreCase(method)) {
            log.debug("Skipping OPTIONS request");
            return true;
        }

        // Skip public endpoints
        if (path.equals("/auth/login") || path.equals("/auth/whoami")) {
            log.debug("Skipping public auth endpoint: {}", path);
            return true;
        }

        // Skip documentation endpoints
        if (path.startsWith("/v3/api-docs") || path.startsWith("/swagger-ui") || path.equals("/swagger-ui.html")) {
            log.debug("Skipping documentation endpoint: {}", path);
            return true;
        }

        // Skip public actuator endpoints
        if (path.equals("/actuator/health") || path.equals("/actuator/info") || path.equals("/actuator/prometheus")) {
            log.debug("Skipping public actuator endpoint: {}", path);
            return true;
        }

        // Filter everything else (including /cases/**)
        log.debug("Will filter request: {} {}", method, path);
        return false;
    }

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain chain) throws IOException, ServletException {

        final String path = request.getRequestURI();
        final String method = request.getMethod();

        log.debug("Processing JWT filter for: {} {}", method, path);

        try {
            // Extract Authorization header
            String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
            log.debug("Authorization header: {}", authHeader != null ? "Bearer ***" : "null");

            if (!StringUtils.hasText(authHeader) || !authHeader.startsWith("Bearer ")) {
                log.warn("No valid Authorization header found for: {} {}", method, path);
                chain.doFilter(request, response);
                return;
            }

            String token = authHeader.substring(7).trim();
            if (!StringUtils.hasText(token)) {
                log.warn("Empty token found for: {} {}", method, path);
                chain.doFilter(request, response);
                return;
            }

            // Validate token and extract subject
            var subjectOpt = jwt.getSubject(token);
            if (subjectOpt.isEmpty()) {
                log.warn("Invalid or expired token for: {} {}", method, path);
                chain.doFilter(request, response);
                return;
            }

            String subject = subjectOpt.get();
            Set<String> roles = jwt.getRoles(token);
            log.info("JWT authenticated user: {} with roles: {} for: {} {}", subject, roles, method, path);

            // Convert roles to authorities (add ROLE_ prefix if not present)
            Set<SimpleGrantedAuthority> authorities = roles.stream()
                    .map(role -> role.startsWith("ROLE_") ? role : "ROLE_" + role)
                    .map(SimpleGrantedAuthority::new)
                    .collect(Collectors.toSet());

            // Set authentication in security context
            UsernamePasswordAuthenticationToken authentication =
                    new UsernamePasswordAuthenticationToken(subject, null, authorities);
            SecurityContextHolder.getContext().setAuthentication(authentication);
            log.debug("Set authentication for user: {} with authorities: {}", subject, authorities);

            // Handle tenant context - prefer JWT claim over header
            var tenantIdOpt = jwt.getTenantId(token);
            if (tenantIdOpt.isPresent()) {
                try {
                    UUID tenantId = UUID.fromString(tenantIdOpt.get());
                    TenantContext.setTenantId(tenantId);
                    log.debug("Set tenant context from JWT: {}", tenantId);
                } catch (IllegalArgumentException e) {
                    log.warn("Invalid tenant ID in JWT token: {}", tenantIdOpt.get());
                }
            } else {
                // Fallback to X-Tenant-Id header
                String tenantHeader = request.getHeader("X-Tenant-Id");
                if (StringUtils.hasText(tenantHeader)) {
                    try {
                        UUID tenantId = UUID.fromString(tenantHeader.trim());
                        TenantContext.setTenantId(tenantId);
                        log.debug("Set tenant context from header: {}", tenantId);
                    } catch (IllegalArgumentException e) {
                        log.warn("Invalid tenant ID in header: {}", tenantHeader);
                    }
                }
            }

            log.info("Successfully authenticated {} for {} {} with tenant: {}",
                    subject, method, path, TenantContext.getTenantId());

            chain.doFilter(request, response);

        } catch (Exception e) {
            log.error("Error in JWT filter for {} {}: {}", method, path, e.getMessage(), e);
            SecurityContextHolder.clearContext();
            chain.doFilter(request, response);
        } finally {
            // Always clear tenant context after request
            TenantContext.clear();
        }
    }
}