// ==============================================================================
// Step 2A: Field-Level Encryption Service
// Create: src/main/java/com/payshield/frauddetector/infrastructure/encryption/FieldEncryptionService.java
// ==============================================================================

package com.payshield.frauddetector.infrastructure.encryption;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.Map;

@Service
public class FieldEncryptionService {

    private static final Logger log = LoggerFactory.getLogger(FieldEncryptionService.class);

    // AES-GCM configuration
    private static final String ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES/GCM/NoPadding";
    private static final int GCM_IV_LENGTH = 12; // 96 bits
    private static final int GCM_TAG_LENGTH = 16; // 128 bits
    private static final int AES_KEY_LENGTH = 32; // 256 bits

    private final SecretKeySpec secretKey;
    private final int keyVersion;
    private final SecureRandom secureRandom;
    private final ObjectMapper objectMapper;

    public FieldEncryptionService(
            @Value("${PSP_AES_KEY:}") String base64Key, // ✅ Changed from ${app.encryption.key} to ${PSP_AES_KEY}
            @Value("${app.encryption.key-version:1}") int keyVersion,
            ObjectMapper objectMapper) {
        
        this.keyVersion = keyVersion;
        this.secureRandom = new SecureRandom();
        this.objectMapper = objectMapper;

        // Validate and decode the encryption key
        if (base64Key == null || base64Key.isBlank()) {
            throw new IllegalArgumentException("Encryption key is required. Set app.encryption.key property.");
        }

        try {
            byte[] decodedKey = Base64.getDecoder().decode(base64Key);
            if (decodedKey.length != AES_KEY_LENGTH) {
                throw new IllegalArgumentException(
                    String.format("Invalid key length: %d bytes. Expected %d bytes for AES-256.", 
                    decodedKey.length, AES_KEY_LENGTH));
            }
            this.secretKey = new SecretKeySpec(decodedKey, ALGORITHM);
            log.info("✅ Field encryption initialized - Algorithm: AES-256-GCM, KeyVersion: {}", keyVersion);
        } catch (IllegalArgumentException e) {
            log.error("❌ Failed to initialize encryption key: {}", e.getMessage());
            throw new IllegalStateException("Invalid encryption key configuration", e);
        }
    }

    /**
     * Encrypt a string field using AES-256-GCM
     * Returns Base64-encoded encrypted data with embedded IV and metadata
     */
    public String encrypt(String plaintext) {
        if (plaintext == null || plaintext.isBlank()) {
            return null;
        }

        try {
            // Generate random IV for each encryption
            byte[] iv = new byte[GCM_IV_LENGTH];
            secureRandom.nextBytes(iv);

            // Initialize cipher
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, iv);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, gcmSpec);

            // Encrypt the plaintext
            byte[] encryptedData = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));

            // Create envelope with metadata
            EncryptionEnvelope envelope = new EncryptionEnvelope(
                keyVersion,
                TRANSFORMATION,
                Base64.getEncoder().encodeToString(iv),
                Base64.getEncoder().encodeToString(encryptedData)
            );

            // Serialize and encode the envelope
            String envelopeJson = objectMapper.writeValueAsString(envelope);
            String result = Base64.getEncoder().encodeToString(envelopeJson.getBytes(StandardCharsets.UTF_8));

            log.debug("✅ Field encrypted successfully - KeyVersion: {}, Length: {}", keyVersion, result.length());
            return result;

        } catch (Exception e) {
            log.error("❌ Encryption failed: {}", e.getMessage(), e);
            throw new EncryptionException("Failed to encrypt field", e);
        }
    }

    /**
     * Decrypt a string field using AES-256-GCM
     * Handles envelope format with embedded IV and metadata
     */
    public String decrypt(String encryptedData) {
        if (encryptedData == null || encryptedData.isBlank()) {
            return null;
        }

        try {
            // Decode the envelope
            byte[] envelopeBytes = Base64.getDecoder().decode(encryptedData);
            String envelopeJson = new String(envelopeBytes, StandardCharsets.UTF_8);
            EncryptionEnvelope envelope = objectMapper.readValue(envelopeJson, EncryptionEnvelope.class);

            // Validate envelope
            if (!TRANSFORMATION.equals(envelope.algorithm())) {
                throw new EncryptionException("Unsupported encryption algorithm: " + envelope.algorithm());
            }

            // Decode IV and encrypted data
            byte[] iv = Base64.getDecoder().decode(envelope.iv());
            byte[] ciphertext = Base64.getDecoder().decode(envelope.data());

            // Initialize cipher for decryption
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, iv);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, gcmSpec);

            // Decrypt the data
            byte[] decryptedBytes = cipher.doFinal(ciphertext);
            String result = new String(decryptedBytes, StandardCharsets.UTF_8);

            log.debug("✅ Field decrypted successfully - KeyVersion: {}", envelope.keyVersion());
            return result;

        } catch (JsonProcessingException e) {
            log.error("❌ Invalid encryption envelope format: {}", e.getMessage());
            throw new EncryptionException("Invalid encrypted data format", e);
        } catch (Exception e) {
            log.error("❌ Decryption failed: {}", e.getMessage(), e);
            throw new EncryptionException("Failed to decrypt field", e);
        }
    }

    /**
     * Generate a SHA-256 hash of the input for duplicate detection
     * This allows searching encrypted fields without decryption
     */
    public String generateHash(String input) {
        if (input == null || input.isBlank()) {
            return null;
        }

        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hashBytes = digest.digest(input.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hashBytes);
        } catch (NoSuchAlgorithmException e) {
            throw new EncryptionException("SHA-256 algorithm not available", e);
        }
    }

    /**
     * Encrypt multiple fields at once for better performance
     */
    public Map<String, String> encryptFields(Map<String, String> fields) {
        if (fields == null || fields.isEmpty()) {
            return new HashMap<>();
        }

        Map<String, String> encrypted = new HashMap<>();
        for (Map.Entry<String, String> entry : fields.entrySet()) {
            String encryptedValue = encrypt(entry.getValue());
            if (encryptedValue != null) {
                encrypted.put(entry.getKey(), encryptedValue);
            }
        }
        return encrypted;
    }

    /**
     * Decrypt multiple fields at once for better performance
     */
    public Map<String, String> decryptFields(Map<String, String> encryptedFields) {
        if (encryptedFields == null || encryptedFields.isEmpty()) {
            return new HashMap<>();
        }

        Map<String, String> decrypted = new HashMap<>();
        for (Map.Entry<String, String> entry : encryptedFields.entrySet()) {
            String decryptedValue = decrypt(entry.getValue());
            if (decryptedValue != null) {
                decrypted.put(entry.getKey(), decryptedValue);
            }
        }
        return decrypted;
    }

    /**
     * Check if data appears to be encrypted (has envelope format)
     */
    public boolean isEncrypted(String data) {
        if (data == null || data.isBlank()) {
            return false;
        }

        try {
            byte[] decoded = Base64.getDecoder().decode(data);
            String json = new String(decoded, StandardCharsets.UTF_8);
            EncryptionEnvelope envelope = objectMapper.readValue(json, EncryptionEnvelope.class);
            return envelope.keyVersion() != null && envelope.algorithm() != null;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Get current key version for audit purposes
     */
    public int getCurrentKeyVersion() {
        return keyVersion;
    }

    /**
     * Encryption envelope for metadata
     */
    public record EncryptionEnvelope(
        Integer keyVersion,
        String algorithm,
        String iv,
        String data
    ) {}

    /**
     * Custom exception for encryption operations
     */
    public static class EncryptionException extends RuntimeException {
        public EncryptionException(String message) {
            super(message);
        }

        public EncryptionException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}