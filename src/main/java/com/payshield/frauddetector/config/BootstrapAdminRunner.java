package com.payshield.frauddetector.config;

import com.payshield.frauddetector.infrastructure.jpa.SpringUserRepository;
import com.payshield.frauddetector.infrastructure.jpa.UserEntity;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Set;
import java.util.UUID;

@Configuration
public class BootstrapAdminRunner {

    private static final Logger log = LoggerFactory.getLogger(BootstrapAdminRunner.class);

    @Bean
    ApplicationRunner seedFirstAdmin(
            SpringUserRepository users,
            PasswordEncoder encoder,
            JdbcTemplate jdbcTemplate,  // Add JdbcTemplate for direct SQL
            @Value("${bootstrap.admin.email:}") String adminEmail,
            @Value("${bootstrap.admin.password:}") String adminPassword,
            @Value("${bootstrap.defaultTenantId:}") String defaultTenantId
    ) {
        return args -> {
            if (adminEmail == null || adminEmail.isBlank() || adminPassword == null || adminPassword.isBlank()) {
                log.warn("Bootstrap admin not created - set bootstrap.admin.email and bootstrap.admin.password");
                return;
            }

            UUID tenantId = null;
            try {
                tenantId = defaultTenantId != null && !defaultTenantId.isBlank()
                        ? UUID.fromString(defaultTenantId)
                        : UUID.randomUUID();
            } catch (Exception e) {
                tenantId = UUID.randomUUID();
            }

            // FIXED: Create tenant record first if it doesn't exist
            try {
                // Check if tenant exists
                Long tenantCount = jdbcTemplate.queryForObject(
                        "SELECT COUNT(*) FROM tenant WHERE id = ?",
                        Long.class,
                        tenantId
                );

                if (tenantCount == 0) {
                    // Create tenant record
                    jdbcTemplate.update(
                            "INSERT INTO tenant (id, name) VALUES (?, ?)",
                            tenantId,
                            "Default Tenant"
                    );
                    log.info("Created tenant record: {} (Default Tenant)", tenantId);
                } else {
                    log.info("Tenant already exists: {}", tenantId);
                }
            } catch (Exception e) {
                log.error("Failed to create/check tenant: {}", e.getMessage(), e);
                return;
            }

            // Now create admin user if it doesn't exist
            if (users.existsByEmail(adminEmail.toLowerCase())) {
                log.info("Bootstrap admin exists: {}", adminEmail);
                return;
            }

            UserEntity u = new UserEntity();
            u.setId(UUID.randomUUID());
            u.setEmail(adminEmail.toLowerCase());
            u.setPasswordHash(encoder.encode(adminPassword));
            u.setTenantId(tenantId);
            u.setRoles(Set.of("ADMIN", "ANALYST", "APPROVER"));
            users.save(u);

            log.info("Bootstrap admin created: {} (tenantId={})", adminEmail, tenantId);
        };
    }
}