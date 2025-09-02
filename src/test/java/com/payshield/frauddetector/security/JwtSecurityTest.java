// ==============================================================================
// FIXED: JwtSecurityTest.java - Correct AssertJ assertions
// ==============================================================================

package com.payshield.frauddetector.security;

import com.payshield.frauddetector.config.JwtService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest
@ActiveProfiles("test")
class JwtSecurityTest {

    @Autowired
    private JwtService jwtService;

    @Test
    void shouldGenerateValidToken() {
        UUID tenantId = UUID.randomUUID();
        String token = jwtService.generateToken("test@example.com", tenantId, Set.of("ADMIN"));

        assertThat(token).isNotEmpty();
        assertThat(jwtService.getSubject(token)).contains("test@example.com");
        assertThat(jwtService.getTenantId(token)).contains(tenantId.toString());
    }

    @Test
    void shouldRejectInvalidToken() {
        assertThat(jwtService.getSubject("invalid-token")).isEmpty();
    }

    @Test
    void shouldExtractRolesCorrectly() {
        Set<String> roles = Set.of("ADMIN", "ANALYST");
        String token = jwtService.generateToken("test@example.com", UUID.randomUUID(), roles);

        // FIXED: Use correct AssertJ method
        assertThat(jwtService.getRoles(token)).containsExactlyInAnyOrder("ADMIN", "ANALYST");

        // Alternative methods that also work:
        // assertThat(jwtService.getRoles(token)).isEqualTo(roles);
        // assertThat(jwtService.getRoles(token)).containsAll(roles);
    }

    @Test
    void shouldHandleEmptyRoles() {
        String token = jwtService.generateToken("test@example.com", UUID.randomUUID(), Set.of());

        assertThat(jwtService.getRoles(token)).isEmpty();
    }

    @Test
    void shouldHandleSingleRole() {
        String token = jwtService.generateToken("test@example.com", UUID.randomUUID(), Set.of("ANALYST"));

        assertThat(jwtService.getRoles(token)).containsExactly("ANALYST");
    }

    @Test
    void shouldValidateTokenExpiration() {
        // Test with very short TTL would require modifying JwtService constructor
        // For now, test that a valid token doesn't report as expired
        String token = jwtService.generateToken("test@example.com", UUID.randomUUID(), Set.of("ADMIN"));

        assertThat(jwtService.isTokenExpired(token)).isFalse();
    }

    @Test
    void shouldExtractTenantIdCorrectly() {
        UUID expectedTenantId = UUID.fromString("12345678-1234-1234-1234-123456789012");
        String token = jwtService.generateToken("test@example.com", expectedTenantId, Set.of("ADMIN"));

        assertThat(jwtService.getTenantId(token))
                .isPresent()
                .contains(expectedTenantId.toString());
    }
}

// ==============================================================================
// ALTERNATIVE: If you prefer the original assertion style
// ==============================================================================

/*
@Test
void shouldExtractRolesCorrectly() {
    Set<String> roles = Set.of("ADMIN", "ANALYST");
    String token = jwtService.generateToken("test@example.com", UUID.randomUUID(), roles);
    
    Set<String> extractedRoles = jwtService.getRoles(token);
    
    // Method 1: Direct equality check
    assertThat(extractedRoles).isEqualTo(roles);
    
    // Method 2: Contains all elements
    assertThat(extractedRoles).containsAll(roles);
    assertThat(extractedRoles).hasSize(roles.size());
    
    // Method 3: Individual checks
    assertThat(extractedRoles).contains("ADMIN", "ANALYST");
    assertThat(extractedRoles).hasSize(2);
}
*/

// ==============================================================================
// Add these dependencies to your pom.xml if missing:
// ==============================================================================

/*
<dependency>
    <groupId>org.assertj</groupId>
    <artifactId>assertj-core</artifactId>
    <scope>test</scope>
</dependency>
*/