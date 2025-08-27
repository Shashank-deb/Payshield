package com.payshield.frauddetector.domain.ports;

import java.io.InputStream;
import java.nio.file.Path;
import java.util.UUID;

public interface FileStoragePort {

    Path store(UUID tenantId, String sha256, String originalFilename, InputStream body);
}
