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

        log.info("JwtAuthFilter: Checking request - {} {}", method, path);

        // Skip OPTIONS requests completely
        if ("OPTIONS".equalsIgnoreCase(method)) {
            log.info("JwtAuthFilter: Skipping OPTIONS request for {}", path);
            return true;
        }

        // Skip public endpoints
        if (path.equals("/auth/login") || path.equals("/auth/whoami")) {
            log.info("JwtAuthFilter: Skipping public auth endpoint: {}", path);
            return true;
        }

        // Skip debug endpoints for testing
        if (path.startsWith("/debug/")) {
            log.info("JwtAuthFilter: Skipping debug endpoint: {}", path);
            return true;
        }

        // Skip documentation endpoints
        if (path.startsWith("/v3/api-docs") || path.startsWith("/swagger-ui") || path.equals("/swagger-ui.html")) {
            log.info("JwtAuthFilter: Skipping documentation endpoint: {}", path);
            return true;
        }

        // Skip public actuator endpoints
        if (path.equals("/actuator/health") || path.equals("/actuator/info") || path.equals("/actuator/prometheus")) {
            log.info("JwtAuthFilter: Skipping public actuator endpoint: {}", path);
            return true;
        }

        // Filter everything else
        log.info("JwtAuthFilter: Will process authentication for: {} {}", method, path);
        return false;
    }

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain chain) throws IOException, ServletException {

        final String path = request.getRequestURI();
        final String method = request.getMethod();

        log.info("JwtAuthFilter: Processing authentication for: {} {}", method, path);

        try {
            // Extract Authorization header
            String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
            log.info("JwtAuthFilter: Authorization header present: {}", authHeader != null ? "YES" : "NO");

            if (!StringUtils.hasText(authHeader) || !authHeader.startsWith("Bearer ")) {
                log.warn("JwtAuthFilter: No valid Authorization header found for: {} {}", method, path);
                log.warn("JwtAuthFilter: Auth header value: {}", authHeader != null ? "Bearer ***" : "null");

                // Don't return here - let Spring Security handle the authentication failure
                chain.doFilter(request, response);
                return;
            }

            String token = authHeader.substring(7).trim();
            if (!StringUtils.hasText(token)) {
                log.warn("JwtAuthFilter: Empty token found for: {} {}", method, path);
                chain.doFilter(request, response);
                return;
            }

            log.info("JwtAuthFilter: Token extracted successfully, validating...");

            // Validate token and extract subject
            var subjectOpt = jwt.getSubject(token);
            if (subjectOpt.isEmpty()) {
                log.warn("JwtAuthFilter: Invalid or expired token for: {} {}", method, path);
                chain.doFilter(request, response);
                return;
            }

            String subject = subjectOpt.get();
            Set<String> roles = jwt.getRoles(token);
            log.info("JwtAuthFilter: JWT authenticated user: {} with roles: {} for: {} {}", subject, roles, method, path);

            // Convert roles to authorities (add ROLE_ prefix if not present)
            Set<SimpleGrantedAuthority> authorities = roles.stream()
                    .map(role -> role.startsWith("ROLE_") ? role : "ROLE_" + role)
                    .map(SimpleGrantedAuthority::new)
                    .collect(Collectors.toSet());

            // Set authentication in security context
            UsernamePasswordAuthenticationToken authentication =
                    new UsernamePasswordAuthenticationToken(subject, null, authorities);
            SecurityContextHolder.getContext().setAuthentication(authentication);
            log.info("JwtAuthFilter: Set authentication for user: {} with authorities: {}", subject, authorities);

            // SECURITY FIX: Get tenant ONLY from JWT token - NEVER trust user headers
            var tenantIdOpt = jwt.getTenantId(token);
            if (tenantIdOpt.isPresent()) {
                try {
                    UUID tenantId = UUID.fromString(tenantIdOpt.get());
                    TenantContext.setTenantId(tenantId);
                    log.info("JwtAuthFilter: Set tenant context from JWT: {}", tenantId);
                } catch (IllegalArgumentException e) {
                    log.warn("JwtAuthFilter: Invalid tenant ID in JWT token: {}", tenantIdOpt.get());
                }
            }

            // REMOVED SECURITY VULNERABILITY:
            // No fallback to X-Tenant-Id header - headers are user-controlled and cannot be trusted!
            // The old code allowed tenant spoofing by changing the X-Tenant-Id header

            log.info("JwtAuthFilter: Successfully authenticated {} for {} {} with tenant: {}",
                    subject, method, path, TenantContext.getTenantId());

            // Continue with the filter chain
            log.info("JwtAuthFilter: Continuing filter chain for {} {}", method, path);
            chain.doFilter(request, response);
            log.info("JwtAuthFilter: Completed processing for {} {}", method, path);

        } catch (Exception e) {
            log.error("JwtAuthFilter: Error in JWT filter for {} {}: {}", method, path, e.getMessage(), e);
            SecurityContextHolder.clearContext();

            // Important: Still continue the chain to let Spring Security handle the error
            chain.doFilter(request, response);
        } finally {
            // Always clear tenant context after request
            TenantContext.clear();
            log.debug("JwtAuthFilter: Cleared tenant context for {} {}", method, path);
        }
    }
}