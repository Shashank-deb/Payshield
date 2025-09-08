// ==============================================================================
// COMPLETE FIXED: MfaService.java - Corrected MFA Verification Flow
// File: src/main/java/com/payshield/frauddetector/application/MfaService.java
// ==============================================================================

package com.payshield.frauddetector.application;

import com.payshield.frauddetector.domain.mfa.MfaConfiguration;
import com.payshield.frauddetector.domain.mfa.MfaStatus;
import com.payshield.frauddetector.domain.mfa.TrustedDevice;
import com.payshield.frauddetector.exception.MfaAlreadyConfiguredException;
import com.payshield.frauddetector.infrastructure.encryption.FieldEncryptionService;
import com.payshield.frauddetector.infrastructure.jpa.*;
import com.payshield.frauddetector.infrastructure.mfa.TOTPService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.OffsetDateTime;
import java.util.*;
import java.util.stream.Collectors;

@Service
public class MfaService {

    private static final Logger log = LoggerFactory.getLogger(MfaService.class);

    private final TOTPService totpService;
    private final FieldEncryptionService encryptionService;
    private final SpringMfaConfigurationRepository mfaConfigRepo;
    private final SpringMfaBackupCodeRepository backupCodeRepo;
    private final SpringMfaTrustedDeviceRepository trustedDeviceRepo;
    private final SpringMfaAuthAttemptRepository authAttemptRepo;
    private final SpringUserRepository userRepository;

    // Configuration
    private final int maxAttempts;
    private final int lockoutDurationMinutes;
    private final int windowMinutes;
    private final boolean trustedDevicesEnabled;
    private final int trustedDeviceExpiryDays;

    public MfaService(
            TOTPService totpService,
            FieldEncryptionService encryptionService,
            SpringMfaConfigurationRepository mfaConfigRepo,
            SpringMfaBackupCodeRepository backupCodeRepo,
            SpringMfaTrustedDeviceRepository trustedDeviceRepo,
            SpringMfaAuthAttemptRepository authAttemptRepo,
            SpringUserRepository userRepository,
            @Value("${app.mfa.rate-limiting.max-attempts:5}") int maxAttempts,
            @Value("${app.mfa.rate-limiting.lockout-duration-minutes:60}") int lockoutDurationMinutes,
            @Value("${app.mfa.rate-limiting.window-minutes:15}") int windowMinutes,
            @Value("${app.mfa.trusted-devices.enabled:true}") boolean trustedDevicesEnabled,
            @Value("${app.mfa.trusted-devices.expiry-days:30}") int trustedDeviceExpiryDays) {

        this.totpService = totpService;
        this.encryptionService = encryptionService;
        this.mfaConfigRepo = mfaConfigRepo;
        this.backupCodeRepo = backupCodeRepo;
        this.trustedDeviceRepo = trustedDeviceRepo;
        this.authAttemptRepo = authAttemptRepo;
        this.userRepository = userRepository;
        this.maxAttempts = maxAttempts;
        this.lockoutDurationMinutes = lockoutDurationMinutes;
        this.windowMinutes = windowMinutes;
        this.trustedDevicesEnabled = trustedDevicesEnabled;
        this.trustedDeviceExpiryDays = trustedDeviceExpiryDays;

        log.info("✅ MFA Service initialized - MaxAttempts: {}, LockoutDuration: {}min, TrustedDevices: {}",
                maxAttempts, lockoutDurationMinutes, trustedDevicesEnabled);
    }

    /**
     * Initialize MFA setup for a user
     */
    @Transactional
    public MfaSetupResult initiateMfaSetup(UUID userId, UUID tenantId, String email) {
        log.info("🔧 Initiating MFA setup for user: {} in tenant: {}", userId, tenantId);

        try {
            // Check if MFA is already configured
            Optional<MfaConfigurationEntity> existing = mfaConfigRepo.findByUserIdAndTenantId(userId, tenantId);
            if (existing.isPresent() && existing.get().isSetupComplete()) {
                throw new IllegalStateException("MFA is already configured for this user");
            }

            // Generate TOTP setup
            TOTPService.TotpSetupResult totpSetup = totpService.setupTotp(email);

            // Encrypt the secret
            String encryptedSecret = encryptionService.encrypt(totpSetup.getSecret());
            String secretHash = encryptionService.generateHash(totpSetup.getSecret());

            // Create or update MFA configuration
            MfaConfigurationEntity config = existing.orElse(new MfaConfigurationEntity());
            config.setUserId(userId);
            config.setTenantId(tenantId);
            config.setEncryptedSecret(encryptedSecret);
            config.setSecretHash(secretHash);
            config.setStatus(MfaConfigurationEntity.MfaStatusType.PENDING);
            config.setSetupComplete(false);
            config.setFailedAttempts(0);
            config.setEncryptionKeyVersion(encryptionService.getCurrentKeyVersion());

            mfaConfigRepo.save(config);

            // Encrypt backup codes and store them
            storeBackupCodes(userId, tenantId, totpSetup.getBackupCodes());

            log.info("✅ MFA setup initiated successfully for user: {}", userId);

            return new MfaSetupResult(
                    totpSetup.getQrCodeUri(),
                    totpSetup.getQrCodeImage(),
                    totpSetup.getBackupCodes(),
                    totpSetup.getSecret()
            );

        } catch (Exception e) {
            log.error("❌ Failed to initiate MFA setup for user {}: {}", userId, e.getMessage(), e);
            throw new RuntimeException("Failed to initiate MFA setup", e);
        }
    }

    /**
     * ✅ FIXED: Complete MFA setup by verifying the first TOTP code
     */
    @Transactional
    public MfaVerificationResult completeMfaSetup(UUID userId, UUID tenantId, String totpCode,
                                                  String deviceFingerprint, String ipAddress, String userAgent) {
        log.info("🔧 Completing MFA setup for user: {} with TOTP code", userId);

        try {
            // Get pending MFA configuration
            MfaConfigurationEntity config = mfaConfigRepo.findByUserIdAndTenantId(userId, tenantId)
                    .orElseThrow(() -> new IllegalStateException("No MFA setup found for user"));

            if (config.isSetupComplete()) {
                throw new MfaAlreadyConfiguredException("MFA setup has already been completed for this user");
            }

            // Decrypt secret and verify code
            String secret = encryptionService.decrypt(config.getEncryptedSecret());
            log.debug("🔓 Decrypted TOTP secret for setup verification");

            // ✅ KEY FIX: Use primary TOTP verification method
            boolean isValid = totpService.verifyCode(secret, totpCode);

            log.info("🔍 TOTP code '{}' verification result: {}", totpCode, isValid);

            // Log attempt
            logAuthAttempt(userId, tenantId, "TOTP_SETUP", isValid, totpCode,
                    ipAddress, userAgent, deviceFingerprint, false,
                    isValid ? null : "INVALID_CODE");

            if (!isValid) {
                log.warn("❌ TOTP setup verification failed for user: {}", userId);
                return new MfaVerificationResult(false, "Invalid TOTP code", false);
            }

            // Complete setup
            config.setSetupComplete(true);
            config.setStatus(MfaConfigurationEntity.MfaStatusType.ENABLED);
            config.setSetupCompletedAt(OffsetDateTime.now());
            config.setLastUsedAt(OffsetDateTime.now());
            config.setBackupCodesRemaining((int)backupCodeRepo.countUnusedByUser(userId));

            mfaConfigRepo.save(config);

            // Update user's MFA status
            updateUserMfaStatus(userId, true);

            // Create trusted device if enabled
            UUID trustedDeviceId = null;
            if (trustedDevicesEnabled && deviceFingerprint != null) {
                trustedDeviceId = createTrustedDevice(userId, tenantId, deviceFingerprint,
                        ipAddress, userAgent, "Setup Device");
            }

            log.info("✅ MFA setup completed successfully for user: {}", userId);

            return new MfaVerificationResult(true, "MFA setup completed successfully",
                    trustedDeviceId != null);

        } catch (MfaAlreadyConfiguredException e) {
            // Re-throw MfaAlreadyConfiguredException directly to be handled by GlobalExceptionHandler
            log.error("❌ MFA already configured for user {}: {}", userId, e.getMessage());
            throw e;
        } catch (Exception e) {
            log.error("❌ Failed to complete MFA setup for user {}: {}", userId, e.getMessage(), e);
            throw new RuntimeException("Failed to complete MFA setup", e);
        }
    }

    /**
     * ✅ FIXED: Verify MFA code during authentication
     */
    @Transactional
    public MfaVerificationResult verifyMfaCode(UUID userId, UUID tenantId, String code,
                                               String deviceFingerprint, String ipAddress, String userAgent) {
        log.info("🔍 Verifying MFA code for user: {} from device: {}", userId, deviceFingerprint);

        try {
            // Check if device is trusted
            if (trustedDevicesEnabled && isTrustedDevice(userId, deviceFingerprint)) {
                log.info("✅ Trusted device detected, bypassing MFA for user: {}", userId);
                updateTrustedDeviceLastSeen(userId, deviceFingerprint);
                return new MfaVerificationResult(true, "Trusted device - MFA bypassed", true);
            }

            // Get MFA configuration
            MfaConfigurationEntity config = mfaConfigRepo.findByUserIdAndTenantId(userId, tenantId)
                    .orElseThrow(() -> new IllegalStateException("MFA not configured for user"));

            // Check if user is locked
            if (isUserLocked(config)) {
                log.warn("❌ MFA verification attempted for locked user: {}", userId);
                logAuthAttempt(userId, tenantId, "TOTP", false, code, ipAddress, userAgent,
                        deviceFingerprint, false, "USER_LOCKED");
                return new MfaVerificationResult(false, "Account temporarily locked due to failed attempts", false);
            }

            // Check rate limiting
            if (isRateLimited(userId)) {
                log.warn("❌ Rate limited MFA attempt for user: {}", userId);
                logAuthAttempt(userId, tenantId, "TOTP", false, code, ipAddress, userAgent,
                        deviceFingerprint, false, "RATE_LIMITED");
                return new MfaVerificationResult(false, "Too many attempts, please try again later", false);
            }

            // Decrypt secret
            String secret = encryptionService.decrypt(config.getEncryptedSecret());

            // ✅ KEY FIX: Try TOTP verification first
            boolean isValidTotp = totpService.verifyCode(secret, code);

            if (isValidTotp) {
                log.info("✅ TOTP verification successful for user: {}", userId);
                handleSuccessfulAuth(config, userId, tenantId, deviceFingerprint, ipAddress, userAgent, "TOTP");
                return new MfaVerificationResult(true, "TOTP verified successfully", false);
            }

            // Try backup code verification
            boolean isValidBackupCode = verifyBackupCode(userId, tenantId, code, ipAddress);
            if (isValidBackupCode) {
                log.info("✅ Backup code verification successful for user: {}", userId);
                handleSuccessfulAuth(config, userId, tenantId, deviceFingerprint, ipAddress, userAgent, "BACKUP_CODE");
                return new MfaVerificationResult(true, "Backup code verified successfully", false);
            }

            // Both failed - increment failed attempts
            handleFailedAuth(config, userId, tenantId, code, deviceFingerprint, ipAddress, userAgent);
            return new MfaVerificationResult(false, "Invalid authentication code", false);

        } catch (Exception e) {
            log.error("❌ MFA verification failed for user {}: {}", userId, e.getMessage(), e);
            throw new RuntimeException("MFA verification failed", e);
        }
    }

    /**
     * Generate new backup codes
     */
    @Transactional
    public List<String> regenerateBackupCodes(UUID userId, UUID tenantId) {
        log.info("🔄 Regenerating backup codes for user: {}", userId);

        try {
            // Delete existing backup codes
            backupCodeRepo.deleteAllByUserId(userId);

            // Generate new backup codes
            List<String> newCodes = totpService.generateBackupCodes();
            storeBackupCodes(userId, tenantId, newCodes);

            // Update MFA configuration
            MfaConfigurationEntity config = mfaConfigRepo.findByUserIdAndTenantId(userId, tenantId)
                    .orElseThrow(() -> new IllegalStateException("MFA not configured"));

            config.setBackupCodesRemaining(newCodes.size());
            config.setBackupCodesGeneratedAt(OffsetDateTime.now());
            mfaConfigRepo.save(config);

            log.info("✅ Backup codes regenerated for user: {}", userId);
            return newCodes;

        } catch (Exception e) {
            log.error("❌ Failed to regenerate backup codes for user {}: {}", userId, e.getMessage(), e);
            throw new RuntimeException("Failed to regenerate backup codes", e);
        }
    }

    /**
     * Disable MFA for a user
     */
    @Transactional
    public void disableMfa(UUID userId, UUID tenantId) {
        log.info("🔄 Disabling MFA for user: {}", userId);

        try {
            MfaConfigurationEntity config = mfaConfigRepo.findByUserIdAndTenantId(userId, tenantId)
                    .orElseThrow(() -> new IllegalStateException("MFA not configured"));

            config.setStatus(MfaConfigurationEntity.MfaStatusType.DISABLED);
            mfaConfigRepo.save(config);

            // Revoke all trusted devices
            revokeTrustedDevices(userId);

            // Update user's MFA status
            updateUserMfaStatus(userId, false);

            log.info("✅ MFA disabled for user: {}", userId);

        } catch (Exception e) {
            log.error("❌ Failed to disable MFA for user {}: {}", userId, e.getMessage(), e);
            throw new RuntimeException("Failed to disable MFA", e);
        }
    }

    /**
     * Get MFA status for a user
     */
    public MfaStatusResult getMfaStatus(UUID userId, UUID tenantId) {
        try {
            Optional<MfaConfigurationEntity> config = mfaConfigRepo.findByUserIdAndTenantId(userId, tenantId);

            if (config.isEmpty()) {
                return new MfaStatusResult(false, MfaStatus.PENDING, false, 0, null, Collections.emptyList());
            }

            MfaConfigurationEntity mfaConfig = config.get();
            List<MfaTrustedDeviceEntity> trustedDevices = trustedDeviceRepo.findActiveTrustedDevices(userId, OffsetDateTime.now());

            return new MfaStatusResult(
                    mfaConfig.isSetupComplete(),
                    MfaStatus.valueOf(mfaConfig.getStatus().name()),
                    mfaConfig.isSetupComplete() && mfaConfig.getStatus() == MfaConfigurationEntity.MfaStatusType.ENABLED,
                    mfaConfig.getBackupCodesRemaining(),
                    mfaConfig.getLastUsedAt(),
                    trustedDevices.stream()
                            .map(this::entityToDomain)
                            .collect(Collectors.toList())
            );

        } catch (Exception e) {
            log.error("❌ Failed to get MFA status for user {}: {}", userId, e.getMessage(), e);
            throw new RuntimeException("Failed to get MFA status", e);
        }
    }

    /**
     * Trust a device for MFA bypass
     */
    @Transactional
    public UUID trustDevice(UUID userId, UUID tenantId, String deviceFingerprint,
                            String deviceName, String ipAddress, String userAgent) {
        if (!trustedDevicesEnabled) {
            throw new IllegalStateException("Trusted devices are not enabled");
        }

        return createTrustedDevice(userId, tenantId, deviceFingerprint, ipAddress, userAgent, deviceName);
    }

    /**
     * Revoke a trusted device
     */
    @Transactional
    public void revokeTrustedDevice(UUID userId, UUID deviceId, UUID revokedBy) {
        log.info("🔄 Revoking trusted device {} for user: {}", deviceId, userId);

        try {
            trustedDeviceRepo.revokeDevice(deviceId, OffsetDateTime.now(), revokedBy);
            log.info("✅ Trusted device revoked: {}", deviceId);

        } catch (Exception e) {
            log.error("❌ Failed to revoke trusted device {}: {}", deviceId, e.getMessage(), e);
            throw new RuntimeException("Failed to revoke trusted device", e);
        }
    }

    // ========================================================================
    // PRIVATE HELPER METHODS
    // ========================================================================

    private List<String> storeBackupCodes(UUID userId, UUID tenantId, List<String> codes) {
        List<String> encryptedCodes = new ArrayList<>();

        for (String code : codes) {
            try {
                String encryptedCode = encryptionService.encrypt(code);
                String codeHash = encryptionService.generateHash(code);

                MfaBackupCodeEntity entity = new MfaBackupCodeEntity();
                entity.setUserId(userId);
                entity.setTenantId(tenantId);
                entity.setEncryptedCode(encryptedCode);
                entity.setCodeHash(codeHash);
                entity.setEncryptionKeyVersion(encryptionService.getCurrentKeyVersion());

                backupCodeRepo.save(entity);
                encryptedCodes.add(encryptedCode);

            } catch (Exception e) {
                log.error("Failed to encrypt backup code: {}", e.getMessage(), e);
                throw new RuntimeException("Failed to store backup codes", e);
            }
        }

        return encryptedCodes;
    }

    private boolean verifyBackupCode(UUID userId, UUID tenantId, String providedCode, String ipAddress) {
        try {
            String codeHash = encryptionService.generateHash(providedCode);
            Optional<MfaBackupCodeEntity> codeEntity = backupCodeRepo.findByCodeHashAndIsUsedFalse(codeHash);

            if (codeEntity.isPresent() && codeEntity.get().getUserId().equals(userId)) {
                // Mark as used
                backupCodeRepo.markAsUsed(codeEntity.get().getId(), OffsetDateTime.now(), ipAddress);

                // Update remaining count
                MfaConfigurationEntity config = mfaConfigRepo.findByUserIdAndTenantId(userId, tenantId)
                        .orElseThrow(() -> new IllegalStateException("MFA config not found"));
                config.setBackupCodesRemaining(Math.max(0, config.getBackupCodesRemaining() - 1));
                mfaConfigRepo.save(config);

                log.info("✅ Backup code used successfully for user: {}", userId);
                return true;
            }

            return false;

        } catch (Exception e) {
            log.error("Error verifying backup code for user {}: {}", userId, e.getMessage(), e);
            return false;
        }
    }

    private boolean isTrustedDevice(UUID userId, String deviceFingerprint) {
        if (deviceFingerprint == null) return false;

        try {
            List<MfaTrustedDeviceEntity> trustedDevices = trustedDeviceRepo.findActiveTrustedDevices(userId, OffsetDateTime.now());
            return trustedDevices.stream()
                    .anyMatch(device -> deviceFingerprint.equals(device.getDeviceFingerprint()));

        } catch (Exception e) {
            log.error("Error checking trusted device for user {}: {}", userId, e.getMessage(), e);
            return false;
        }
    }

    private void updateTrustedDeviceLastSeen(UUID userId, String deviceFingerprint) {
        try {
            Optional<MfaTrustedDeviceEntity> device = trustedDeviceRepo.findByUserIdAndDeviceFingerprint(userId, deviceFingerprint);
            if (device.isPresent()) {
                trustedDeviceRepo.updateLastSeen(device.get().getId(), OffsetDateTime.now());
            }
        } catch (Exception e) {
            log.error("Error updating trusted device last seen: {}", e.getMessage(), e);
        }
    }

    private UUID createTrustedDevice(UUID userId, UUID tenantId, String deviceFingerprint,
                                     String ipAddress, String userAgent, String deviceName) {
        try {
            MfaTrustedDeviceEntity device = new MfaTrustedDeviceEntity();
            device.setUserId(userId);
            device.setTenantId(tenantId);
            device.setDeviceFingerprint(deviceFingerprint);
            device.setDeviceName(deviceName);
            device.setIpAddress(ipAddress);
            device.setUserAgent(userAgent);
            device.setTrusted(true);
            device.setExpiresAt(OffsetDateTime.now().plusDays(trustedDeviceExpiryDays));

            MfaTrustedDeviceEntity saved = trustedDeviceRepo.save(device);
            log.info("✅ Created trusted device for user {}: {}", userId, saved.getId());
            return saved.getId();

        } catch (Exception e) {
            log.error("Failed to create trusted device for user {}: {}", userId, e.getMessage(), e);
            throw new RuntimeException("Failed to create trusted device", e);
        }
    }

    private boolean isUserLocked(MfaConfigurationEntity config) {
        return config.getStatus() == MfaConfigurationEntity.MfaStatusType.LOCKED ||
                (config.getLockedUntil() != null && config.getLockedUntil().isAfter(OffsetDateTime.now()));
    }

    private boolean isRateLimited(UUID userId) {
        try {
            OffsetDateTime since = OffsetDateTime.now().minusMinutes(windowMinutes);
            long failedAttempts = authAttemptRepo.countFailedAttemptsSince(userId, since);
            return failedAttempts >= maxAttempts;

        } catch (Exception e) {
            log.error("Error checking rate limit for user {}: {}", userId, e.getMessage(), e);
            return false;
        }
    }

    private void handleSuccessfulAuth(MfaConfigurationEntity config, UUID userId, UUID tenantId,
                                      String deviceFingerprint, String ipAddress, String userAgent, String type) {
        try {
            // Reset failed attempts and update last used
            mfaConfigRepo.updateLastUsed(userId, OffsetDateTime.now());

            // Log successful attempt
            logAuthAttempt(userId, tenantId, type, true, null, ipAddress, userAgent,
                    deviceFingerprint, isTrustedDevice(userId, deviceFingerprint), null);

        } catch (Exception e) {
            log.error("Error handling successful auth for user {}: {}", userId, e.getMessage(), e);
        }
    }

    private void handleFailedAuth(MfaConfigurationEntity config, UUID userId, UUID tenantId, String code,
                                  String deviceFingerprint, String ipAddress, String userAgent) {
        try {
            int newFailedAttempts = config.getFailedAttempts() + 1;

            if (newFailedAttempts >= maxAttempts) {
                // Lock the user
                OffsetDateTime lockUntil = OffsetDateTime.now().plusMinutes(lockoutDurationMinutes);
                mfaConfigRepo.updateLockStatus(userId, MfaConfigurationEntity.MfaStatusType.LOCKED,
                        lockUntil, OffsetDateTime.now());
                log.warn("❌ User {} locked due to {} failed MFA attempts", userId, newFailedAttempts);
            } else {
                // Just increment failed attempts
                mfaConfigRepo.updateFailedAttempts(userId, newFailedAttempts, OffsetDateTime.now());
            }

            // Log failed attempt
            logAuthAttempt(userId, tenantId, "TOTP", false, code, ipAddress, userAgent,
                    deviceFingerprint, false, "INVALID_CODE");

        } catch (Exception e) {
            log.error("Error handling failed auth for user {}: {}", userId, e.getMessage(), e);
        }
    }

    private void logAuthAttempt(UUID userId, UUID tenantId, String type, boolean success,
                                String providedCode, String ipAddress, String userAgent,
                                String deviceFingerprint, boolean isTrustedDevice, String failureReason) {
        try {
            MfaAuthAttemptEntity attempt = new MfaAuthAttemptEntity();
            attempt.setUserId(userId);
            attempt.setTenantId(tenantId);
            attempt.setAttemptType(type);
            attempt.setSuccess(success);
            attempt.setProvidedCode(providedCode);
            attempt.setIpAddress(ipAddress);
            attempt.setUserAgent(userAgent);
            attempt.setDeviceFingerprint(deviceFingerprint);
            attempt.setIsTrustedDevice(isTrustedDevice);
            attempt.setFailureReason(failureReason);

            authAttemptRepo.save(attempt);

        } catch (Exception e) {
            log.error("Error logging MFA attempt for user {}: {}", userId, e.getMessage(), e);
        }
    }

    private void updateUserMfaStatus(UUID userId, boolean enabled) {
        try {
            Optional<UserEntity> user = userRepository.findById(userId);
            if (user.isPresent()) {
                UserEntity userEntity = user.get();
                userEntity.setMfaEnabled(enabled);
                if (enabled) {
                    userEntity.setLastMfaSetupAt(OffsetDateTime.now());
                }
                userRepository.save(userEntity);

                log.debug("✅ Updated MFA status for user {} to: {}", userId, enabled);
            } else {
                log.warn("❌ User not found when updating MFA status: {}", userId);
            }
        } catch (Exception e) {
            log.error("Error updating user MFA status for user {}: {}", userId, e.getMessage(), e);
        }
    }

    private void revokeTrustedDevices(UUID userId) {
        try {
            List<MfaTrustedDeviceEntity> devices = trustedDeviceRepo.findByUserIdAndIsTrustedTrueAndRevokedAtIsNull(userId);
            for (MfaTrustedDeviceEntity device : devices) {
                trustedDeviceRepo.revokeDevice(device.getId(), OffsetDateTime.now(), userId);
            }
            log.info("✅ Revoked {} trusted devices for user: {}", devices.size(), userId);

        } catch (Exception e) {
            log.error("Error revoking trusted devices for user {}: {}", userId, e.getMessage(), e);
        }
    }

    private TrustedDevice entityToDomain(MfaTrustedDeviceEntity entity) {
        return new TrustedDevice(
                entity.getId(),
                entity.getUserId(),
                entity.getTenantId(),
                entity.getDeviceFingerprint(),
                entity.getDeviceName(),
                entity.getUserAgent(),
                entity.getIpAddress(),
                entity.getLocation(),
                entity.isTrusted(),
                entity.getTrustedAt(),
                entity.getExpiresAt(),
                entity.getLastSeenAt(),
                entity.getRevokedAt(),
                entity.getRevokedBy(),
                entity.getCreatedAt()
        );
    }

    // ========================================================================
    // RESULT CLASSES
    // ========================================================================

    public static class MfaSetupResult {
        private final String qrCodeUri;
        private final String qrCodeImage;
        private final List<String> backupCodes;
        private final String secret;

        public MfaSetupResult(String qrCodeUri, String qrCodeImage, List<String> backupCodes, String secret) {
            this.qrCodeUri = qrCodeUri;
            this.qrCodeImage = qrCodeImage;
            this.backupCodes = backupCodes;
            this.secret = secret;
        }

        public String getQrCodeUri() { return qrCodeUri; }
        public String getQrCodeImage() { return qrCodeImage; }
        public List<String> getBackupCodes() { return backupCodes; }
        public String getSecret() { return secret; }
    }

    public static class MfaVerificationResult {
        private final boolean success;
        private final String message;
        private final boolean trustedDevice;

        public MfaVerificationResult(boolean success, String message, boolean trustedDevice) {
            this.success = success;
            this.message = message;
            this.trustedDevice = trustedDevice;
        }

        public boolean isSuccess() { return success; }
        public String getMessage() { return message; }
        public boolean isTrustedDevice() { return trustedDevice; }
    }

    public static class MfaStatusResult {
        private final boolean isSetup;
        private final MfaStatus status;
        private final boolean isEnabled;
        private final int backupCodesRemaining;
        private final OffsetDateTime lastUsedAt;
        private final List<TrustedDevice> trustedDevices;

        public MfaStatusResult(boolean isSetup, MfaStatus status, boolean isEnabled,
                               int backupCodesRemaining, OffsetDateTime lastUsedAt,
                               List<TrustedDevice> trustedDevices) {
            this.isSetup = isSetup;
            this.status = status;
            this.isEnabled = isEnabled;
            this.backupCodesRemaining = backupCodesRemaining;
            this.lastUsedAt = lastUsedAt;
            this.trustedDevices = trustedDevices;
        }

        public boolean isSetup() { return isSetup; }
        public MfaStatus getStatus() { return status; }
        public boolean isEnabled() { return isEnabled; }
        public int getBackupCodesRemaining() { return backupCodesRemaining; }
        public OffsetDateTime getLastUsedAt() { return lastUsedAt; }
        public List<TrustedDevice> getTrustedDevices() { return trustedDevices; }
    }
}