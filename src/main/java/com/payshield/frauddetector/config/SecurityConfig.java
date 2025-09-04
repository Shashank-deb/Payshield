package com.payshield.frauddetector.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;

@Configuration
@EnableMethodSecurity(prePostEnabled = true) // ✅ Enable @PreAuthorize annotations
public class SecurityConfig {

  private static final Logger log = LoggerFactory.getLogger(SecurityConfig.class);

  @Bean
  public PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder();
  }

  @Bean
  public CorsConfigurationSource corsConfigurationSource() {
    CorsConfiguration configuration = new CorsConfiguration();

    // Allow specific origins (configure these based on your frontend domains)
    configuration.setAllowedOriginPatterns(Arrays.asList("*")); // Be more specific in production

    // Allow common HTTP methods
    configuration.setAllowedMethods(Arrays.asList(
            "GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"
    ));

    // Allow common headers
    configuration.setAllowedHeaders(Arrays.asList(
            "Authorization",
            "Content-Type",
            "X-Requested-With",
            "Accept",
            "Origin",
            "Access-Control-Request-Method",
            "Access-Control-Request-Headers",
            "X-Tenant-Id",
            "Idempotency-Key",
            "X-Sender-Domain"
    ));

    // Allow credentials (cookies, authorization headers)
    configuration.setAllowCredentials(true);

    // Cache preflight requests for 1 hour
    configuration.setMaxAge(3600L);

    UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
    source.registerCorsConfiguration("/**", configuration);
    return source;
  }

  @Bean
  SecurityFilterChain security(HttpSecurity http, JwtService jwtService) throws Exception {
    log.info("Configuring security filter chain with encryption admin endpoints");

    JwtAuthFilter jwtFilter = new JwtAuthFilter(jwtService);

    http
            // IMPORTANT: Disable CSRF for REST APIs with JWT authentication
            .csrf(csrf -> csrf.disable())

            // Enable CORS
            .cors(cors -> cors.configurationSource(corsConfigurationSource()))

            // Stateless session management for JWT
            .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS))

            // Configure request matchers
            .authorizeHttpRequests(auth -> {
              log.info("Configuring authorization rules with admin encryption endpoints");
              auth
                      // Public endpoints - no authentication required
                      .requestMatchers(HttpMethod.OPTIONS, "/**").permitAll() // Allow all preflight requests
                      .requestMatchers("/auth/login", "/auth/whoami").permitAll()
                      .requestMatchers("/debug/**").permitAll() // Allow debug endpoints for testing
                      .requestMatchers("/v3/api-docs/**", "/swagger-ui/**", "/swagger-ui.html").permitAll()
                      .requestMatchers("/actuator/health", "/actuator/info", "/actuator/prometheus").permitAll()

                      // ✅ Admin-only endpoints (UPDATED)
                      .requestMatchers("/actuator/**").hasRole("ADMIN")
                      .requestMatchers("/outbox/**").hasRole("ADMIN") // Outbox testing endpoints for admins only
                      .requestMatchers("/admin/**").hasRole("ADMIN") // ✅ NEW: Admin encryption endpoints

                      // Invoice endpoints - analysts and admins can upload, all roles can view
                      .requestMatchers(HttpMethod.POST, "/invoices/upload").hasAnyRole("ANALYST", "ADMIN")
                      .requestMatchers("/invoices/**").hasAnyRole("ANALYST", "ADMIN", "APPROVER")

                      // Cases endpoints - specifically require APPROVER or ADMIN
                      .requestMatchers(HttpMethod.POST, "/cases/*/approve").hasAnyRole("APPROVER", "ADMIN")
                      .requestMatchers(HttpMethod.POST, "/cases/*/reject").hasAnyRole("APPROVER", "ADMIN")
                      .requestMatchers("/cases/**").hasAnyRole("APPROVER", "ADMIN")

                      // ✅ Fraud detection testing endpoints - available to analysts and admins
                      .requestMatchers("/fraud/**").hasAnyRole("ANALYST", "ADMIN")

                      // All other requests require authentication
                      .anyRequest().authenticated();
            })

            // Add custom JWT filter
            .addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class)

            // Custom exception handling
            .exceptionHandling(e -> e
                    .authenticationEntryPoint(json401())
                    .accessDeniedHandler(json403())
            );

    log.info("Security filter chain configured successfully with encryption admin support");
    return http.build();
  }

  private AuthenticationEntryPoint json401() {
    return (request, response, ex) -> {
      log.warn("Authentication failed for {} {}: {}",
              request.getMethod(), request.getRequestURI(), ex.getMessage());

      response.setStatus(401);
      response.setContentType("application/json");
      response.setCharacterEncoding("UTF-8");
      response.setHeader("Access-Control-Allow-Origin", "*");
      response.setHeader("Access-Control-Allow-Credentials", "true");
      response.getWriter().write(
              "{\"error\":\"Unauthorized\"," +
                      "\"message\":\"Valid Bearer token required\"," +
                      "\"path\":\"" + request.getRequestURI() + "\"}"
      );
    };
  }

  private AccessDeniedHandler json403() {
    return (request, response, ex) -> {
      log.warn("Access denied for {} {}: {}",
              request.getMethod(), request.getRequestURI(), ex.getMessage());

      response.setStatus(403);
      response.setContentType("application/json");
      response.setCharacterEncoding("UTF-8");
      response.setHeader("Access-Control-Allow-Origin", "*");
      response.setHeader("Access-Control-Allow-Credentials", "true");
      response.getWriter().write(
              "{\"error\":\"Forbidden\"," +
                      "\"message\":\"Insufficient role\"," +
                      "\"path\":\"" + request.getRequestURI() + "\"}"
      );
    };
  }
}