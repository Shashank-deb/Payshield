package com.payshield.frauddetector.domain.ports;

import com.payshield.frauddetector.domain.Vendor;

import java.util.Optional;
import java.util.UUID;

public interface VendorHistoryRepository {
    Optional<Vendor> findByName(UUID tenantId, String vendorName);
    Vendor save(Vendor vendor);
}
