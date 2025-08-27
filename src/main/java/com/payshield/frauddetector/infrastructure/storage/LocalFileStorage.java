package com.payshield.frauddetector.infrastructure.storage;

import com.payshield.frauddetector.config.AppProperties;
import com.payshield.frauddetector.domain.ports.FileStoragePort;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.*;
import java.util.UUID;

@Component
public class LocalFileStorage implements FileStoragePort {
    private final AppProperties props;
    public LocalFileStorage(AppProperties props){ this.props = props; }

    @Override
    public Path store(UUID tenantId, String sha256, String originalFilename, InputStream body) {
        // Ignore client-provided filename and store as <sha256>.pdf to prevent path/PII leakage
        String safeName = sha256 + ".pdf";

        Path dir = Path.of(props.getStorage().getBasePath(), tenantId.toString(), sha256.substring(0,2));
        Path file = dir.resolve(safeName);
        try {
            Files.createDirectories(dir);
            // Overwrite if same content arrives again (idempotent by sha256)
            Files.copy(body, file, StandardCopyOption.REPLACE_EXISTING);
        } catch (IOException e) {
            throw new RuntimeException("Could not store file", e);
        }
        return file;
    }
}
