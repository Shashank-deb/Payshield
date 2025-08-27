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
import java.util.Enumeration;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

/**
 * Robust stateless JWT filter that:
 *  - Never writes a 401 by itself (lets Spring entrypoint do it).
 *  - Accepts multiple Authorization headers and any capitalization/spacing of the 'Bearer ' prefix.
 *  - Sets tenant from 'tenantId'/'tid' claim or X-Tenant-Id header.
 */
public class JwtAuthFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(JwtAuthFilter.class);
    private final JwtService jwt;

    public JwtAuthFilter(JwtService jwt) {
        this.jwt = jwt;
    }

    @Override
    protected boolean shouldNotFilter(@NonNull HttpServletRequest req) {
        String p = req.getRequestURI();
        if ("OPTIONS".equalsIgnoreCase(req.getMethod())) return true;
        if (p.equals("/auth/login") || p.equals("/auth/whoami")) return true;
        if (p.startsWith("/v3/api-docs") || p.startsWith("/swagger-ui") || p.equals("/swagger-ui.html")) return true;
        if (p.equals("/actuator/health") || p.equals("/actuator/info") || p.equals("/actuator/prometheus")) return true;
        return false; // Do NOT skip /cases/**
    }

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain chain) throws IOException, ServletException {

        final String path = request.getRequestURI();

        try {
            // Parse Authorization header(s) in a robust way
            String token = null;
            Enumeration<String> headers = request.getHeaders(HttpHeaders.AUTHORIZATION);
            while (headers != null && headers.hasMoreElements()) {
                String raw = headers.nextElement();
                if (!StringUtils.hasText(raw)) continue;
                String h = raw.trim();
                if (h.length() >= 7 && h.regionMatches(true, 0, "Bearer ", 0, 7)) {
                    token = h.substring(7).trim();
                    if (StringUtils.hasText(token)) break;
                }
            }

            // No usable token → proceed; secured endpoints will be handled by entrypoint
            if (!StringUtils.hasText(token)) {
                chain.doFilter(request, response);
                return;
            }

            var subjectOpt = jwt.getSubject(token);
            if (subjectOpt.isEmpty()) {
                chain.doFilter(request, response);
                return;
            }

            Set<SimpleGrantedAuthority> authorities = jwt.getRoles(token).stream()
                    .map(r -> r.startsWith("ROLE_") ? r : "ROLE_" + r)
                    .map(SimpleGrantedAuthority::new)
                    .collect(Collectors.toSet());

            SecurityContextHolder.getContext().setAuthentication(
                    new UsernamePasswordAuthenticationToken(subjectOpt.get(), null, authorities)
            );

            // Multi-tenant: prefer claim, else header
            jwt.getTenantId(token).ifPresentOrElse(
                    tid -> {
                        try { TenantContext.setTenantId(UUID.fromString(tid)); } catch (Exception ignored) {}
                    },
                    () -> {
                        String h = request.getHeader("X-Tenant-Id");
                        if (StringUtils.hasText(h)) {
                            try { TenantContext.setTenantId(UUID.fromString(h)); } catch (Exception ignored) {}
                        }
                    }
            );

            if (path.startsWith("/cases/")) {
                log.info("JWT OK for {}: sub={}, roles={}, tenant={}", path, subjectOpt.get(), authorities, TenantContext.getTenantId());
            }

            chain.doFilter(request, response);
        } finally {
            TenantContext.clear();
        }
    }
}
