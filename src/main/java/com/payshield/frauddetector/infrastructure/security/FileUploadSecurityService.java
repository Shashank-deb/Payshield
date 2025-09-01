// ==============================================================================
// Step 5: Complete FileUploadSecurityService Implementation
// Create this file: src/main/java/com/payshield/frauddetector/infrastructure/security/FileUploadSecurityService.java
// ==============================================================================

package com.payshield.frauddetector.infrastructure.security;

import org.apache.tika.Tika;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.net.Socket;
import java.util.Set;

@Service
public class FileUploadSecurityService {

    private static final Logger log = LoggerFactory.getLogger(FileUploadSecurityService.class);

    // Only allow PDF files
    private static final Set<String> ALLOWED_MIME_TYPES = Set.of(
            "application/pdf"
    );

    // PDF file signature (magic bytes) - %PDF
    private static final byte[] PDF_SIGNATURE = "%PDF".getBytes();

    // Apache Tika for deep content detection
    private final Tika tika = new Tika();

    // ClamAV configuration
    private final boolean clamAvEnabled;
    private final String clamAvHost;
    private final int clamAvPort;
    private final int clamAvTimeout;
    private final boolean failSecure;
    private final boolean validateContent;
    private final boolean strictMimeCheck;

    public FileUploadSecurityService(
            @Value("${app.clamav.enabled:false}") boolean clamAvEnabled,
            @Value("${app.clamav.host:clamav}") String clamAvHost,
            @Value("${app.clamav.port:3310}") int clamAvPort,
            @Value("${app.clamav.timeout:30000}") int clamAvTimeout,
            @Value("${app.clamav.fail-secure:false}") boolean failSecure,
            @Value("${app.upload.validate-content:true}") boolean validateContent,
            @Value("${app.upload.strict-mime-check:true}") boolean strictMimeCheck) {

        this.clamAvEnabled = clamAvEnabled;
        this.clamAvHost = clamAvHost;
        this.clamAvPort = clamAvPort;
        this.clamAvTimeout = clamAvTimeout;
        this.failSecure = failSecure;
        this.validateContent = validateContent;
        this.strictMimeCheck = strictMimeCheck;

        log.info("FileUploadSecurityService initialized - ClamAV: {}, ContentValidation: {}, StrictMIME: {}",
                clamAvEnabled, validateContent, strictMimeCheck);

        if (clamAvEnabled) {
            log.info("ClamAV configured - Host: {}, Port: {}, Timeout: {}ms, FailSecure: {}",
                    clamAvHost, clamAvPort, clamAvTimeout, failSecure);
        }
    }

    /**
     * Comprehensive file validation including MIME type, file signature, and virus scanning
     */
    public FileValidationResult validateFile(MultipartFile file) {
        long startTime = System.currentTimeMillis();

        try {
            log.info("🛡️  Starting file validation - filename: '{}', declared type: '{}', size: {} bytes",
                    file.getOriginalFilename(), file.getContentType(), file.getSize());

            // 1. Basic file checks
            FileValidationResult basicCheck = performBasicValidation(file);
            if (!basicCheck.isValid()) {
                return basicCheck;
            }

            // 2. MIME type validation (declared by client)
            FileValidationResult mimeCheck = validateMimeType(file);
            if (!mimeCheck.isValid()) {
                return mimeCheck;
            }

            // Get file bytes once for all subsequent checks
            byte[] fileBytes = file.getBytes();

            // 3. File signature validation (magic bytes)
            FileValidationResult signatureCheck = validateFileSignature(fileBytes, file.getOriginalFilename());
            if (!signatureCheck.isValid()) {
                return signatureCheck;
            }

            // 4. Deep content type detection (if enabled)
            if (validateContent) {
                FileValidationResult contentCheck = validateFileContent(fileBytes, file.getOriginalFilename());
                if (!contentCheck.isValid()) {
                    return contentCheck;
                }
            } else {
                log.debug("Content validation disabled, skipping Tika analysis");
            }

            // 5. Virus scanning (if enabled)
            if (clamAvEnabled) {
                FileValidationResult virusCheck = performVirusScan(fileBytes, file.getOriginalFilename());
                if (!virusCheck.isValid()) {
                    return virusCheck;
                }
            } else {
                log.debug("ClamAV scanning disabled, skipping virus check");
            }

            long duration = System.currentTimeMillis() - startTime;
            log.info("✅ File validation successful for '{}' in {}ms", file.getOriginalFilename(), duration);
            return FileValidationResult.success();

        } catch (IOException e) {
            log.error("❌ I/O error during file validation for '{}': {}", file.getOriginalFilename(), e.getMessage());
            return FileValidationResult.failure("File validation failed due to I/O error");
        } catch (Exception e) {
            log.error("❌ Unexpected error during file validation for '{}': {}",
                    file.getOriginalFilename(), e.getMessage(), e);
            return FileValidationResult.failure("File validation failed due to system error");
        }
    }

    /**
     * Basic file validation (size, empty check)
     */
    private FileValidationResult performBasicValidation(MultipartFile file) {
        if (file == null) {
            return FileValidationResult.failure("No file provided");
        }

        if (file.isEmpty()) {
            log.warn("Empty file uploaded: '{}'", file.getOriginalFilename());
            return FileValidationResult.failure("File is empty");
        }

        // 10MB limit - configurable via application properties
        long maxSize = 10 * 1024 * 1024; // 10MB
        if (file.getSize() > maxSize) {
            log.warn("File too large: '{}' - {} bytes (max: {} bytes)",
                    file.getOriginalFilename(), file.getSize(), maxSize);
            return FileValidationResult.failure("File exceeds 10MB limit");
        }

        return FileValidationResult.success();
    }

    /**
     * MIME type validation
     */
    private FileValidationResult validateMimeType(MultipartFile file) {
        String declaredMimeType = file.getContentType();

        if (!strictMimeCheck && (declaredMimeType == null || declaredMimeType.isBlank())) {
            log.debug("MIME type check relaxed, no declared type for: '{}'", file.getOriginalFilename());
            return FileValidationResult.success();
        }

        if (!ALLOWED_MIME_TYPES.contains(declaredMimeType)) {
            log.warn("Invalid declared MIME type '{}' for file: '{}'", declaredMimeType, file.getOriginalFilename());
            return FileValidationResult.failure("Only PDF files are allowed (declared type: " + declaredMimeType + ")");
        }

        log.debug("MIME type validation passed: '{}'", declaredMimeType);
        return FileValidationResult.success();
    }

    /**
     * File signature validation (magic bytes)
     */
    private FileValidationResult validateFileSignature(byte[] fileBytes, String filename) {
        if (fileBytes.length < PDF_SIGNATURE.length) {
            log.warn("File too small for PDF signature check: '{}' - {} bytes", filename, fileBytes.length);
            return FileValidationResult.failure("File too small to be a valid PDF");
        }

        for (int i = 0; i < PDF_SIGNATURE.length; i++) {
            if (fileBytes[i] != PDF_SIGNATURE[i]) {
                log.warn("Invalid PDF file signature for: '{}' - Expected %PDF, got: {}",
                        filename, new String(fileBytes, 0, Math.min(4, fileBytes.length)));
                return FileValidationResult.failure("Invalid PDF file format - file signature mismatch");
            }
        }

        log.debug("PDF file signature validation passed for: '{}'", filename);
        return FileValidationResult.success();
    }

    /**
     * Deep content validation using Apache Tika
     */
    private FileValidationResult validateFileContent(byte[] fileBytes, String filename) {
        try {
            String detectedMimeType = tika.detect(fileBytes);
            log.debug("Tika detected MIME type: '{}' for file: '{}'", detectedMimeType, filename);

            if (!ALLOWED_MIME_TYPES.contains(detectedMimeType)) {
                log.warn("Tika detected invalid content type '{}' for file: '{}' (expected PDF)",
                        detectedMimeType, filename);
                return FileValidationResult.failure(
                        "File content does not match PDF format (detected: " + detectedMimeType + ")");
            }

            log.debug("Content validation passed - Tika confirmed PDF format for: '{}'", filename);
            return FileValidationResult.success();

        } catch (Exception e) {
            log.error("Tika content detection failed for file '{}': {}", filename, e.getMessage());
            return FileValidationResult.failure("Content validation failed");
        }
    }

    /**
     * Virus scanning with ClamAV
     */
    private FileValidationResult performVirusScan(byte[] fileBytes, String filename) {
        try {
            log.debug("Starting ClamAV scan for file: '{}'", filename);
            boolean isClean = scanWithClamAv(fileBytes);

            if (!isClean) {
                log.error("🚨 VIRUS DETECTED in file: '{}'", filename);
                return FileValidationResult.failure("File failed security scan - malware detected");
            }

            log.debug("✅ ClamAV scan passed for file: '{}'", filename);
            return FileValidationResult.success();

        } catch (Exception e) {
            log.error("ClamAV scanning error for file '{}': {}", filename, e.getMessage());

            if (failSecure) {
                log.warn("Failing secure - rejecting file '{}' due to AV unavailability", filename);
                return FileValidationResult.failure("File security scan unavailable - rejected for safety");
            } else {
                log.warn("Failing open - allowing file '{}' despite AV error", filename);
                return FileValidationResult.success();
            }
        }
    }

    /**
     * Scan file with ClamAV antivirus using INSTREAM protocol
     * Returns true if file is clean, false if infected
     */
    private boolean scanWithClamAv(byte[] fileBytes) throws IOException {
        try (Socket socket = new Socket(clamAvHost, clamAvPort)) {
            // Set socket timeout
            socket.setSoTimeout(clamAvTimeout);

            log.debug("Connected to ClamAV at {}:{}", clamAvHost, clamAvPort);

            // Send INSTREAM command to ClamAV
            socket.getOutputStream().write("zINSTREAM\0".getBytes());

            // Send file size as 4-byte big-endian integer
            int fileSize = fileBytes.length;
            byte[] sizeBytes = new byte[4];
            sizeBytes[0] = (byte) (fileSize >>> 24);
            sizeBytes[1] = (byte) (fileSize >>> 16);
            sizeBytes[2] = (byte) (fileSize >>> 8);
            sizeBytes[3] = (byte) fileSize;
            socket.getOutputStream().write(sizeBytes);

            // Send file data
            socket.getOutputStream().write(fileBytes);

            // Send end of stream (0 length)
            socket.getOutputStream().write(new byte[4]);
            socket.getOutputStream().flush();

            // Read response from ClamAV
            byte[] response = new byte[1024];
            int bytesRead = socket.getInputStream().read(response);

            if (bytesRead <= 0) {
                throw new IOException("No response from ClamAV");
            }

            String responseStr = new String(response, 0, bytesRead).trim();
            log.debug("ClamAV response: '{}'", responseStr);

            // Response format: "stream: OK" or "stream: VIRUS_NAME FOUND"
            boolean isClean = responseStr.contains("OK") && !responseStr.contains("FOUND");

            if (!isClean) {
                log.warn("ClamAV detected threat: '{}'", responseStr);
            }

            return isClean;

        } catch (IOException e) {
            log.error("ClamAV connection error: {}", e.getMessage());
            throw e;
        }
    }

    /**
     * Result class for file validation operations
     */
    public static class FileValidationResult {
        private final boolean valid;
        private final String errorMessage;
        private final long timestamp;

        private FileValidationResult(boolean valid, String errorMessage) {
            this.valid = valid;
            this.errorMessage = errorMessage;
            this.timestamp = System.currentTimeMillis();
        }

        public static FileValidationResult success() {
            return new FileValidationResult(true, null);
        }

        public static FileValidationResult failure(String errorMessage) {
            return new FileValidationResult(false, errorMessage);
        }

        public boolean isValid() {
            return valid;
        }

        public String getErrorMessage() {
            return errorMessage;
        }

        public long getTimestamp() {
            return timestamp;
        }

        @Override
        public String toString() {
            return "FileValidationResult{" +
                    "valid=" + valid +
                    ", errorMessage='" + errorMessage + '\'' +
                    ", timestamp=" + timestamp +
                    '}';
        }
    }
}