// ==============================================================================
// COMPLETE: UserEntity.java - Full File with MFA Support
// File: src/main/java/com/payshield/frauddetector/infrastructure/jpa/UserEntity.java
// ==============================================================================

package com.payshield.frauddetector.infrastructure.jpa;

import jakarta.persistence.*;
import java.time.OffsetDateTime;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

@Entity
@Table(name = "users")
public class UserEntity {

    @Id
    private UUID id;

    @Column(nullable = false, unique = true, length = 320)
    private String email;

    @Column(name = "password_hash", nullable = false, length = 100)
    private String passwordHash;

    @Column(name = "tenant_id", nullable = false)
    private UUID tenantId;

    @Column(name = "created_at", nullable = false)
    private OffsetDateTime createdAt = OffsetDateTime.now();

    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(name = "user_roles", joinColumns = @JoinColumn(name = "user_id"))
    @Column(name = "role", nullable = false, length = 32)
    private Set<String> roles = new HashSet<>();

    // ===============================================================================
    // MFA-RELATED FIELDS (Added from V6 migration)
    // ===============================================================================

    @Column(name = "mfa_enabled", nullable = false)
    private Boolean mfaEnabled = false;

    @Column(name = "mfa_enforced", nullable = false)
    private Boolean mfaEnforced = false;

    @Column(name = "last_mfa_setup_at")
    private OffsetDateTime lastMfaSetupAt;

    @Column(name = "mfa_backup_codes_count", nullable = false)
    private Integer mfaBackupCodesCount = 0;

    // ===============================================================================
    // STANDARD GETTERS AND SETTERS
    // ===============================================================================

    public UUID getId() { return id; }
    public void setId(UUID id) { this.id = id; }

    public String getEmail() { return email; }
    public void setEmail(String email) { this.email = email == null ? null : email.toLowerCase(); }

    public String getPasswordHash() { return passwordHash; }
    public void setPasswordHash(String passwordHash) { this.passwordHash = passwordHash; }

    public UUID getTenantId() { return tenantId; }
    public void setTenantId(UUID tenantId) { this.tenantId = tenantId; }

    public OffsetDateTime getCreatedAt() { return createdAt; }
    public void setCreatedAt(OffsetDateTime createdAt) { this.createdAt = createdAt; }

    public Set<String> getRoles() { return roles; }
    public void setRoles(Set<String> roles) { this.roles = roles; }

    // ===============================================================================
    // MFA-RELATED GETTERS AND SETTERS (FIXED)
    // ===============================================================================

    public Boolean getMfaEnabled() {
        return mfaEnabled != null ? mfaEnabled : false;
    }

    public void setMfaEnabled(Boolean mfaEnabled) {
        this.mfaEnabled = mfaEnabled != null ? mfaEnabled : false;
    }

    public Boolean getMfaEnforced() {
        return mfaEnforced != null ? mfaEnforced : false;
    }

    public void setMfaEnforced(Boolean mfaEnforced) {
        this.mfaEnforced = mfaEnforced != null ? mfaEnforced : false;
    }

    public OffsetDateTime getLastMfaSetupAt() {
        return lastMfaSetupAt;
    }

    public void setLastMfaSetupAt(OffsetDateTime lastMfaSetupAt) {
        this.lastMfaSetupAt = lastMfaSetupAt;
    }

    public Integer getMfaBackupCodesCount() {
        return mfaBackupCodesCount != null ? mfaBackupCodesCount : 0;
    }

    public void setMfaBackupCodesCount(Integer mfaBackupCodesCount) {
        this.mfaBackupCodesCount = mfaBackupCodesCount != null ? mfaBackupCodesCount : 0;
    }

    // ===============================================================================
    // CONVENIENCE METHODS FOR MFA
    // ===============================================================================

    /**
     * Check if MFA is enabled and properly configured for this user
     */
    public boolean isMfaEnabled() {
        return getMfaEnabled();
    }

    /**
     * Check if MFA is enforced for this user (admin required)
     */
    public boolean isMfaEnforced() {
        return getMfaEnforced();
    }

    /**
     * Check if user has any admin-related roles that might require MFA
     */
    public boolean hasAdminRole() {
        return roles != null && (roles.contains("ADMIN") || roles.contains("ROLE_ADMIN"));
    }

    /**
     * Check if MFA setup is required for this user
     */
    public boolean requiresMfaSetup() {
        return isMfaEnforced() || (hasAdminRole() && !isMfaEnabled());
    }

    @Override
    public String toString() {
        return "UserEntity{" +
                "id=" + id +
                ", email='" + email + '\'' +
                ", tenantId=" + tenantId +
                ", mfaEnabled=" + mfaEnabled +
                ", mfaEnforced=" + mfaEnforced +
                ", roles=" + roles +
                ", createdAt=" + createdAt +
                '}';
    }
}