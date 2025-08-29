package com.payshield.frauddetector.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
public class SecurityConfig {

  private static final Logger log = LoggerFactory.getLogger(SecurityConfig.class);

  @Bean
  public PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder();
  }

  @Bean
  SecurityFilterChain security(HttpSecurity http, JwtService jwtService) throws Exception {
    log.info("Configuring security filter chain");

    JwtAuthFilter jwtFilter = new JwtAuthFilter(jwtService);

    http
            .csrf(csrf -> csrf.disable())
            .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .authorizeHttpRequests(auth -> {
              log.info("Configuring authorization rules");
              auth
                      // Public endpoints - no authentication required
                      .requestMatchers("/auth/login", "/auth/whoami").permitAll()
                      .requestMatchers("/v3/api-docs/**", "/swagger-ui/**", "/swagger-ui.html").permitAll()
                      .requestMatchers("/actuator/health", "/actuator/info", "/actuator/prometheus").permitAll()

                      // Admin-only endpoints
                      .requestMatchers("/actuator/**").hasRole("ADMIN")
                      .requestMatchers("/outbox/**").hasRole("ADMIN") // Outbox testing endpoints for admins only

                      // Invoice endpoints - analysts and admins can upload, all roles can view
                      .requestMatchers(HttpMethod.POST, "/invoices/upload").hasAnyRole("ANALYST", "ADMIN")
                      .requestMatchers("/invoices/**").hasAnyRole("ANALYST", "ADMIN", "APPROVER")

                      // Cases endpoints - specifically require APPROVER or ADMIN
                      .requestMatchers(HttpMethod.POST, "/cases/*/approve").hasAnyRole("APPROVER", "ADMIN")
                      .requestMatchers(HttpMethod.POST, "/cases/*/reject").hasAnyRole("APPROVER", "ADMIN")
                      .requestMatchers("/cases/**").hasAnyRole("APPROVER", "ADMIN")

                      // All other requests require authentication
                      .anyRequest().authenticated();
            })
            .addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class)
            .exceptionHandling(e -> e
                    .authenticationEntryPoint(json401())
                    .accessDeniedHandler(json403())
            );

    log.info("Security filter chain configured successfully");
    return http.build();
  }

  private AuthenticationEntryPoint json401() {
    return (request, response, ex) -> {
      log.warn("Authentication failed for {} {}: {}",
              request.getMethod(), request.getRequestURI(), ex.getMessage());

      response.setStatus(401);
      response.setContentType("application/json");
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
      response.getWriter().write(
              "{\"error\":\"Forbidden\"," +
                      "\"message\":\"Insufficient role\"," +
                      "\"path\":\"" + request.getRequestURI() + "\"}"
      );
    };
  }
}