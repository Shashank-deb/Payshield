package com.payshield.frauddetector.application;

import java.io.InputStream;
import java.math.BigDecimal;
import java.util.Optional;
import java.util.UUID;

public class UploadInvoiceCommand {
    public final UUID tenantId;
    public final String vendorName;
    public final Optional<String> senderDomain;
    public final BigDecimal statedAmount;
    public final String currency;
    public final String originalFilename;
    public final String idempotencyKey;
    public final InputStream body;

    public UploadInvoiceCommand(UUID tenantId, String vendorName, Optional<String> senderDomain, BigDecimal statedAmount,
                                String currency, String originalFilename, String idempotencyKey, InputStream body) {
        this.tenantId = tenantId;
        this.vendorName = vendorName;
        this.senderDomain = senderDomain;
        this.statedAmount = statedAmount;
        this.currency = currency;
        this.originalFilename = originalFilename;
        this.idempotencyKey = idempotencyKey;
        this.body = body;
    }
}
