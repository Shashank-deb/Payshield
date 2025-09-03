-- Add encrypted columns for PII data
ALTER TABLE invoice
    ADD COLUMN bank_iban_encrypted TEXT,
    ADD COLUMN bank_swift_encrypted TEXT;

-- Add index for encrypted IBAN lookups (if needed for deduplication)
-- Note: We can't index encrypted data directly, so we'd need a hash for searches
ALTER TABLE invoice
    ADD COLUMN bank_iban_hash VARCHAR(64);

-- Create index on IBAN hash for duplicate detection
CREATE INDEX IF NOT EXISTS idx_invoice_iban_hash ON invoice(tenant_id, bank_iban_hash);

-- Add encrypted fields to vendor table
ALTER TABLE vendor
    ADD COLUMN email_domain_encrypted TEXT,
    ADD COLUMN current_bank_last4_encrypted TEXT;

-- Add metadata for encryption key rotation
CREATE TABLE IF NOT EXISTS encryption_metadata (
                                                   id BIGSERIAL PRIMARY KEY,
                                                   key_version INTEGER NOT NULL DEFAULT 1,
                                                   algorithm VARCHAR(50) NOT NULL DEFAULT 'AES-256-GCM',
                                                   created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                                                   retired_at TIMESTAMPTZ,
                                                   is_active BOOLEAN NOT NULL DEFAULT true,

                                                   UNIQUE(key_version)
);

-- Insert initial encryption key version
INSERT INTO encryption_metadata (key_version, algorithm, is_active)
VALUES (1, 'AES-256-GCM', true)
ON CONFLICT (key_version) DO NOTHING;

-- Add audit trail for encryption operations
CREATE TABLE IF NOT EXISTS encryption_audit (
                                                id BIGSERIAL PRIMARY KEY,
                                                tenant_id UUID NOT NULL,
                                                table_name VARCHAR(50) NOT NULL,
                                                record_id UUID NOT NULL,
                                                field_name VARCHAR(50) NOT NULL,
                                                operation VARCHAR(20) NOT NULL, -- 'ENCRYPT', 'DECRYPT', 'KEY_ROTATION'
                                                key_version INTEGER NOT NULL,
                                                performed_by VARCHAR(255) NOT NULL,
                                                performed_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Create index for encryption audit queries
CREATE INDEX IF NOT EXISTS idx_encryption_audit_tenant_time
    ON encryption_audit(tenant_id, performed_at DESC);

-- Comments for documentation
COMMENT ON COLUMN invoice.bank_iban_encrypted IS 'AES-256-GCM encrypted IBAN';
COMMENT ON COLUMN invoice.bank_swift_encrypted IS 'AES-256-GCM encrypted SWIFT code';
COMMENT ON COLUMN invoice.bank_iban_hash IS 'SHA-256 hash of IBAN for duplicate detection';
COMMENT ON TABLE encryption_metadata IS 'Tracks encryption key versions for rotation';
COMMENT ON TABLE encryption_audit IS 'Audit log for all encryption/decryption operations';