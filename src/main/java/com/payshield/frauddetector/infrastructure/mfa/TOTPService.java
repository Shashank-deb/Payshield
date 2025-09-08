// ==============================================================================
// FIXED: TOTPService.java - Corrected TOTP Verification Logic
// File: src/main/java/com/payshield/frauddetector/infrastructure/mfa/TOTPService.java
// ==============================================================================

package com.payshield.frauddetector.infrastructure.mfa;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.qrcode.QRCodeWriter;
import com.warrenstrange.googleauth.GoogleAuthenticator;
import com.warrenstrange.googleauth.GoogleAuthenticatorConfig;
import com.warrenstrange.googleauth.GoogleAuthenticatorKey;
import com.warrenstrange.googleauth.HmacHashFunction;
import dev.samstevens.totp.code.*;
import dev.samstevens.totp.qr.QrData;
import dev.samstevens.totp.qr.QrDataFactory;
import dev.samstevens.totp.secret.DefaultSecretGenerator;
import dev.samstevens.totp.secret.SecretGenerator;
import dev.samstevens.totp.time.SystemTimeProvider;
import dev.samstevens.totp.time.TimeProvider;
import com.payshield.frauddetector.infrastructure.encryption.FieldEncryptionService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.ByteArrayOutputStream;
import java.security.SecureRandom;
import java.util.*;
import java.util.concurrent.TimeUnit;

@Service
public class TOTPService {

    private static final Logger log = LoggerFactory.getLogger(TOTPService.class);

    // Configuration from application.yml
    private final String issuerName;
    private final int digits;
    private final int periodSeconds;
    private final int windowSize;
    private final int qrWidth;
    private final int qrHeight;
    private final int backupCodesCount;
    private final int backupCodeLength;

    private final FieldEncryptionService encryptionService;
    private final SecureRandom secureRandom;
    private final SecretGenerator secretGenerator;
    private final TimeProvider timeProvider;
    private final CodeGenerator codeGenerator;
    private final CodeVerifier codeVerifier;

    // ✅ FIXED: Add Google Authenticator as primary verifier
    private final GoogleAuthenticator googleAuth;

    public TOTPService(
            @Value("${app.mfa.totp.issuer-name:PayShield}") String issuerName,
            @Value("${app.mfa.totp.digits:6}") int digits,
            @Value("${app.mfa.totp.period-seconds:30}") int periodSeconds,
            @Value("${app.mfa.totp.window-size:1}") int windowSize,
            @Value("${app.mfa.qr-code.width:300}") int qrWidth,
            @Value("${app.mfa.qr-code.height:300}") int qrHeight,
            @Value("${app.mfa.backup-codes.count:10}") int backupCodesCount,
            @Value("${app.mfa.backup-codes.length:8}") int backupCodeLength,
            FieldEncryptionService encryptionService) {

        this.issuerName = issuerName;
        this.digits = digits;
        this.periodSeconds = periodSeconds;
        this.windowSize = windowSize;
        this.qrWidth = qrWidth;
        this.qrHeight = qrHeight;
        this.backupCodesCount = backupCodesCount;
        this.backupCodeLength = backupCodeLength;
        this.encryptionService = encryptionService;
        this.secureRandom = new SecureRandom();

        // Initialize TOTP components
        this.secretGenerator = new DefaultSecretGenerator();
        this.timeProvider = new SystemTimeProvider();

        // Create HashingAlgorithm instance
        HashingAlgorithm algorithm = HashingAlgorithm.SHA1;

        // Initialize code generator with proper parameters
        this.codeGenerator = new DefaultCodeGenerator(algorithm, digits);

        // Initialize code verifier
        this.codeVerifier = new DefaultCodeVerifier(codeGenerator, timeProvider);

        // ✅ FIXED: Initialize Google Authenticator with proper config
        GoogleAuthenticatorConfig config = new GoogleAuthenticatorConfig.GoogleAuthenticatorConfigBuilder()
                .setTimeStepSizeInMillis(TimeUnit.SECONDS.toMillis(periodSeconds))
                .setWindowSize(windowSize)
                .setCodeDigits(digits)
                .setHmacHashFunction(HmacHashFunction.HmacSHA1)
                .build();

        this.googleAuth = new GoogleAuthenticator(config);

        log.info("✅ TOTP Service initialized - Issuer: {}, Digits: {}, Period: {}s, Window: {}",
                issuerName, digits, periodSeconds, windowSize);
    }

    /**
     * Generate a new TOTP secret for user setup
     */
    public String generateSecret() {
        try {
            String secret = secretGenerator.generate();
            log.debug("Generated new TOTP secret of length: {} characters", secret.length());
            return secret;
        } catch (Exception e) {
            log.error("Failed to generate TOTP secret: {}", e.getMessage(), e);
            throw new RuntimeException("Failed to generate TOTP secret", e);
        }
    }

    /**
     * Create TOTP URI for QR code generation
     */
    public String createTotpUri(String email, String secret) {
        try {
            // Create QrData manually
            String uri = String.format("otpauth://totp/%s:%s?secret=%s&issuer=%s&algorithm=SHA1&digits=%d&period=%d",
                    issuerName,
                    email,
                    secret,
                    issuerName,
                    digits,
                    periodSeconds);

            log.debug("Generated TOTP URI for user: {}", email);
            return uri;
        } catch (Exception e) {
            log.error("Failed to create TOTP URI for user {}: {}", email, e.getMessage(), e);
            throw new RuntimeException("Failed to create TOTP URI", e);
        }
    }

    /**
     * Generate QR code image as base64 string
     */
    public String generateQrCode(String totpUri) {
        try {
            QRCodeWriter qrCodeWriter = new QRCodeWriter();
            BitMatrix bitMatrix = qrCodeWriter.encode(totpUri, BarcodeFormat.QR_CODE, qrWidth, qrHeight);

            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            MatrixToImageWriter.writeToStream(bitMatrix, "PNG", outputStream);

            String base64Image = Base64.getEncoder().encodeToString(outputStream.toByteArray());
            log.debug("Generated QR code image of size: {} bytes", outputStream.size());
            return base64Image;
        } catch (Exception e) {
            log.error("Failed to generate QR code: {}", e.getMessage(), e);
            throw new RuntimeException("Failed to generate QR code", e);
        }
    }

    /**
     * ✅ FIXED: Primary TOTP verification method using Google Authenticator library
     */
    public boolean verifyCode(String secret, String providedCode) {
        try {
            if (secret == null || secret.isBlank() || providedCode == null || providedCode.isBlank()) {
                log.debug("TOTP verification failed - null or empty secret/code");
                return false;
            }

            // ✅ FIXED: Clean and validate the provided code
            String cleanCode = providedCode.trim();
            if (!cleanCode.matches("^[0-9]{6}$")) {
                log.debug("TOTP verification failed - invalid code format: '{}'", cleanCode);
                return false;
            }

            int code;
            try {
                code = Integer.parseInt(cleanCode);
            } catch (NumberFormatException e) {
                log.debug("TOTP verification failed - could not parse code: '{}'", cleanCode);
                return false;
            }

            // ✅ FIXED: Use Google Authenticator for verification (most reliable)
            boolean isValid = googleAuth.authorize(secret, code);

            if (isValid) {
                log.debug("✅ TOTP code verified successfully using Google Authenticator");
            } else {
                log.debug("❌ TOTP code verification failed using Google Authenticator");

                // ✅ ADDED: Debug information for troubleshooting
                String currentCode = getCurrentCode(secret);
                long timeRemaining = getTimeUntilNextCode();
                log.debug("Debug info - Current expected code: {}, Time until next: {}s",
                        currentCode, timeRemaining);
            }

            return isValid;
        } catch (Exception e) {
            log.error("Error during TOTP verification: {}", e.getMessage(), e);
            return false;
        }
    }

    /**
     * ✅ FIXED: Alternative verification method with detailed logging
     */
    public boolean verifyCodeWithDebug(String secret, String providedCode) {
        try {
            log.info("🔍 Starting TOTP verification with debug info");
            log.info("Secret length: {}, Provided code: '{}'",
                    secret != null ? secret.length() : 0, providedCode);

            if (secret == null || secret.isBlank() || providedCode == null || providedCode.isBlank()) {
                log.warn("❌ TOTP verification failed - null or empty parameters");
                return false;
            }

            // Clean the code
            String cleanCode = providedCode.trim();
            if (!cleanCode.matches("^[0-9]{6}$")) {
                log.warn("❌ TOTP verification failed - invalid format: '{}'", cleanCode);
                return false;
            }

            // Get current time info
            long currentTimeSeconds = System.currentTimeMillis() / 1000;
            long currentTimeSlot = currentTimeSeconds / periodSeconds;
            long timeInCurrentSlot = currentTimeSeconds % periodSeconds;
            long timeUntilNext = periodSeconds - timeInCurrentSlot;

            log.info("🕒 Time info - Current slot: {}, Time in slot: {}s, Until next: {}s",
                    currentTimeSlot, timeInCurrentSlot, timeUntilNext);

            // Generate expected codes for current and adjacent time slots
            List<String> expectedCodes = new ArrayList<>();
            for (int i = -windowSize; i <= windowSize; i++) {
                try {
                    long timeSlot = currentTimeSlot + i;
                    String expectedCode = codeGenerator.generate(secret, timeSlot);
                    expectedCodes.add(expectedCode);
                    log.debug("Expected code for slot {} ({}): {}",
                            timeSlot, i == 0 ? "current" : (i > 0 ? "future" : "past"), expectedCode);
                } catch (Exception e) {
                    log.error("Error generating code for time slot offset {}: {}", i, e.getMessage());
                }
            }

            // Check if provided code matches any expected code
            boolean isValid = expectedCodes.contains(cleanCode);

            if (isValid) {
                log.info("✅ TOTP verification successful - code matches expected");
            } else {
                log.warn("❌ TOTP verification failed - code '{}' doesn't match any expected codes: {}",
                        cleanCode, expectedCodes);
            }

            // Double-check with Google Authenticator
            boolean googleAuthResult = googleAuth.authorize(secret, Integer.parseInt(cleanCode));
            log.info("🔍 Google Authenticator result: {}", googleAuthResult);

            return isValid || googleAuthResult;

        } catch (Exception e) {
            log.error("❌ Error during debug TOTP verification: {}", e.getMessage(), e);
            return false;
        }
    }

    /**
     * Generate backup codes for account recovery
     */
    public List<String> generateBackupCodes() {
        List<String> codes = new ArrayList<>();

        for (int i = 0; i < backupCodesCount; i++) {
            String code = generateBackupCode();
            codes.add(code);
        }

        log.info("Generated {} backup codes", backupCodesCount);
        return codes;
    }

    /**
     * Generate a single backup code
     */
    private String generateBackupCode() {
        String chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        StringBuilder code = new StringBuilder();

        for (int i = 0; i < backupCodeLength; i++) {
            code.append(chars.charAt(secureRandom.nextInt(chars.length())));
        }

        return code.toString();
    }

    /**
     * ✅ FIXED: Get current TOTP code for testing/display purposes
     */
    public String getCurrentCode(String secret) {
        try {
            long currentTime = System.currentTimeMillis() / 1000; // Convert to seconds
            long currentTimeSlot = currentTime / periodSeconds;
            return codeGenerator.generate(secret, currentTimeSlot);
        } catch (Exception e) {
            log.error("Failed to generate current TOTP code: {}", e.getMessage(), e);
            throw new RuntimeException("Failed to generate current TOTP code", e);
        }
    }

    /**
     * Get time remaining until next TOTP code
     */
    public long getTimeUntilNextCode() {
        long currentTime = System.currentTimeMillis() / 1000; // Convert to seconds
        long timeInCurrentStep = currentTime % periodSeconds;
        return periodSeconds - timeInCurrentStep;
    }

    /**
     * Validate backup code format
     */
    public boolean isValidBackupCodeFormat(String code) {
        if (code == null || code.length() != backupCodeLength) {
            return false;
        }
        return code.matches("^[A-Z0-9]+$");
    }

    /**
     * TOTP Setup Result
     */
    public static class TotpSetupResult {
        private final String secret;
        private final String qrCodeUri;
        private final String qrCodeImage;
        private final List<String> backupCodes;

        public TotpSetupResult(String secret, String qrCodeUri, String qrCodeImage, List<String> backupCodes) {
            this.secret = secret;
            this.qrCodeUri = qrCodeUri;
            this.qrCodeImage = qrCodeImage;
            this.backupCodes = backupCodes;
        }

        public String getSecret() { return secret; }
        public String getQrCodeUri() { return qrCodeUri; }
        public String getQrCodeImage() { return qrCodeImage; }
        public List<String> getBackupCodes() { return backupCodes; }
    }

    /**
     * Complete TOTP setup process
     */
    public TotpSetupResult setupTotp(String email) {
        String secret = generateSecret();
        String qrCodeUri = createTotpUri(email, secret);
        String qrCodeImage = generateQrCode(qrCodeUri);
        List<String> backupCodes = generateBackupCodes();

        log.info("Completed TOTP setup for user: {}", email);
        return new TotpSetupResult(secret, qrCodeUri, qrCodeImage, backupCodes);
    }

    /**
     * ✅ ADDED: Test method to verify setup
     */
    public boolean testTotpSetup(String secret, String email) {
        try {
            log.info("🧪 Testing TOTP setup for user: {}", email);

            // Generate current code and verify it
            String currentCode = getCurrentCode(secret);
            log.info("Generated test code: {}", currentCode);

            boolean verificationResult = verifyCode(secret, currentCode);
            log.info("Verification result: {}", verificationResult);

            return verificationResult;
        } catch (Exception e) {
            log.error("TOTP setup test failed: {}", e.getMessage(), e);
            return false;
        }
    }
}