// ==============================================================================
// Step 11: OpenAPI/Swagger Configuration
// Create: src/main/java/com/payshield/frauddetector/config/OpenApiConfig.java
// ==============================================================================

package com.payshield.frauddetector.config;

import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Contact;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.info.License;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import io.swagger.v3.oas.models.security.SecurityScheme;
import io.swagger.v3.oas.models.servers.Server;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.List;

@Configuration
public class OpenApiConfig {

    @Value("${server.port:2406}")
    private String serverPort;

    @Bean
    public OpenAPI payshieldOpenAPI() {
        return new OpenAPI()
                .info(new Info()
                        .title("PayShield Fraud Detection API")
                        .description("""
                                Enterprise fraud detection system for invoice processing with advanced security features.
                                
                                ## Features
                                - JWT-based authentication with role-based access
                                - Secure file upload with virus scanning
                                - Real-time fraud detection engine
                                - Multi-tenant architecture
                                - Comprehensive audit logging
                                
                                ## Authentication
                                All protected endpoints require a Bearer token. Use `/auth/login` to obtain a token.
                                
                                ## Security
                                - File uploads are scanned for malware
                                - All sensitive data is encrypted
                                - Comprehensive input validation
                                """)
                        .version("1.0.0")
                        .contact(new Contact()
                                .name("PayShield Security Team")
                                .email("security@payshield.com")
                                .url("https://payshield.com"))
                        .license(new License()
                                .name("PayShield License")
                                .url("https://payshield.com/license")))
                .servers(List.of(
                        new Server()
                                .url("http://localhost:" + serverPort)
                                .description("Local Development Server"),
                        new Server()
                                .url("https://api.payshield.com")
                                .description("Production Server")))
                .addSecurityItem(new SecurityRequirement().addList("Bearer Authentication"))
                .components(new io.swagger.v3.oas.models.Components()
                        .addSecuritySchemes("Bearer Authentication", 
                                new SecurityScheme()
                                        .type(SecurityScheme.Type.HTTP)
                                        .scheme("bearer")
                                        .bearerFormat("JWT")
                                        .description("Enter JWT Bearer token")));
    }
}