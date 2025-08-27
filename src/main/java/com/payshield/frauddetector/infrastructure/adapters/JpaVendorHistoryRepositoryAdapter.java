package com.payshield.frauddetector.infrastructure.adapters;

import com.payshield.frauddetector.domain.Vendor;
import com.payshield.frauddetector.domain.ports.VendorHistoryRepository;
import com.payshield.frauddetector.infrastructure.jpa.SpringVendorRepository;
import com.payshield.frauddetector.infrastructure.jpa.VendorEntity;
import org.springframework.stereotype.Component;

import java.util.Optional;
import java.util.UUID;

@Component
public class JpaVendorHistoryRepositoryAdapter implements VendorHistoryRepository {
    private final SpringVendorRepository vendors;

    public JpaVendorHistoryRepositoryAdapter(SpringVendorRepository vendors) {
        this.vendors = vendors;
    }

    @Override
    public Optional<Vendor> findByName(UUID tenantId, String vendorName) {
        return vendors.findByTenantIdAndName(tenantId, vendorName)
                .map(e -> new Vendor(e.getId(), e.getTenantId(), e.getName(), e.getEmailDomain(), e.getCurrentBankLast4()));
    }

    @Override
    public Vendor save(Vendor vendor) {
        VendorEntity e = new VendorEntity();
        e.setId(vendor.getId());
        e.setTenantId(vendor.getTenantId());
        e.setName(vendor.getName());
        e.setEmailDomain(vendor.getEmailDomain());
        e.setCurrentBankLast4(vendor.getCurrentBankLast4());
        vendors.save(e);
        return vendor;
    }
}
