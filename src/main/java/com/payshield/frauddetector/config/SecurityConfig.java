package com.payshield.frauddetector.config;

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

  @Bean
  public PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder();
  }

  /** Single chain that applies to the whole application. */
  @Bean
  SecurityFilterChain security(HttpSecurity http, JwtService jwtService) throws Exception {
    JwtAuthFilter jwtFilter = new JwtAuthFilter(jwtService);

    http
            .csrf(csrf -> csrf.disable())
            .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .authorizeHttpRequests(auth -> auth
                    // Public endpoints
                    .requestMatchers("/auth/login", "/auth/whoami").permitAll()
                    .requestMatchers("/v3/api-docs/**", "/swagger-ui/**", "/swagger-ui.html").permitAll()
                    .requestMatchers("/actuator/health", "/actuator/info", "/actuator/prometheus").permitAll()
                    // Secured endpoints
                    .requestMatchers("/actuator/**").hasRole("ADMIN")
                    .requestMatchers(HttpMethod.POST, "/invoices/upload").hasAnyRole("ANALYST","ADMIN")
                    .requestMatchers("/invoices/**").hasAnyRole("ANALYST","ADMIN","APPROVER")
                    .requestMatchers("/cases/**").hasAnyRole("APPROVER","ADMIN")
                    .anyRequest().authenticated()
            )
            .addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class)
            .exceptionHandling(e -> e
                    .authenticationEntryPoint(json401())
                    .accessDeniedHandler(json403())
            );

    return http.build();
  }

  private AuthenticationEntryPoint json401() {
    return (request, response, ex) -> {
      response.setStatus(401);
      response.setContentType("application/json");
      response.getWriter().write("{\"error\":\"Unauthorized\",\"message\":\"Valid Bearer token required\"}");
    };
  }

  private AccessDeniedHandler json403() {
    return (request, response, ex) -> {
      response.setStatus(403);
      response.setContentType("application/json");
      response.getWriter().write("{\"error\":\"Forbidden\",\"message\":\"Insufficient role\"}");
    };
  }
}
