// ==============================================================================
// MFA Status Enumeration
// File: src/main/java/com/payshield/frauddetector/domain/mfa/MfaStatus.java
// ==============================================================================

package com.payshield.frauddetector.domain.mfa;

/**
 * Represents the current status of MFA for a user
 */
public enum MfaStatus {
    /**
     * MFA setup has been initiated but not completed
     */
    PENDING,
    
    /**
     * MFA is fully configured and active
     */
    ENABLED,
    
    /**
     * MFA has been temporarily disabled by user or admin
     */
    DISABLED,
    
    /**
     * MFA is locked due to too many failed attempts
     */
    LOCKED
}