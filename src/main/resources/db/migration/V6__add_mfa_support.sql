-- ==============================================================================
-- V6: Add Multi-Factor Authentication (MFA) Support
-- File: src/main/resources/db/migration/V6__add_mfa_support.sql
-- ==============================================================================

-- MFA Configuration table
CREATE TABLE mfa_configuration (
                                   user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
                                   tenant_id UUID NOT NULL REFERENCES tenant(id) ON DELETE CASCADE,
                                   encrypted_secret TEXT, -- AES-encrypted TOTP secret
                                   secret_hash VARCHAR(64), -- SHA-256 hash for validation
                                   status VARCHAR(20) NOT NULL DEFAULT 'PENDING', -- PENDING, ENABLED, DISABLED, LOCKED
                                   is_setup_complete BOOLEAN NOT NULL DEFAULT FALSE,
                                   setup_completed_at TIMESTAMPTZ,
                                   last_used_at TIMESTAMPTZ,
                                   failed_attempts INTEGER NOT NULL DEFAULT 0,
                                   locked_until TIMESTAMPTZ,
                                   backup_codes_remaining INTEGER NOT NULL DEFAULT 0,
                                   backup_codes_generated_at TIMESTAMPTZ,
                                   encryption_key_version INTEGER NOT NULL DEFAULT 1,
                                   created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                                   updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- MFA Backup Codes table
CREATE TABLE mfa_backup_codes (
                                  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                                  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                                  tenant_id UUID NOT NULL REFERENCES tenant(id) ON DELETE CASCADE,
                                  encrypted_code TEXT NOT NULL, -- AES-encrypted backup code
                                  code_hash VARCHAR(64) NOT NULL, -- SHA-256 hash for lookup
                                  is_used BOOLEAN NOT NULL DEFAULT FALSE,
                                  used_at TIMESTAMPTZ,
                                  used_from_ip INET,
                                  encryption_key_version INTEGER NOT NULL DEFAULT 1,
                                  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Trusted Devices table
CREATE TABLE mfa_trusted_devices (
                                     id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                                     user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                                     tenant_id UUID NOT NULL REFERENCES tenant(id) ON DELETE CASCADE,
                                     device_fingerprint VARCHAR(128) NOT NULL, -- Device identification hash
                                     device_name VARCHAR(100), -- User-friendly device name
                                     user_agent TEXT, -- Browser/device info
                                     ip_address INET, -- IP when device was trusted
                                     location VARCHAR(100), -- Geographic location
                                     is_trusted BOOLEAN NOT NULL DEFAULT TRUE,
                                     trusted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                                     expires_at TIMESTAMPTZ, -- Optional device trust expiration
                                     last_seen_at TIMESTAMPTZ,
                                     revoked_at TIMESTAMPTZ,
                                     revoked_by UUID REFERENCES users(id), -- Who revoked this device
                                     created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- MFA Authentication Attempts table (for security monitoring)
CREATE TABLE mfa_auth_attempts (
                                   id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                                   user_id UUID REFERENCES users(id) ON DELETE SET NULL,
                                   tenant_id UUID REFERENCES tenant(id) ON DELETE SET NULL,
                                   email VARCHAR(320), -- Store email even if user is deleted
                                   attempt_type VARCHAR(20) NOT NULL, -- TOTP, BACKUP_CODE, SMS, etc.
                                   success BOOLEAN NOT NULL,
                                   provided_code VARCHAR(20), -- Store for forensics (hashed)
                                   ip_address INET,
                                   user_agent TEXT,
                                   location VARCHAR(100),
                                   failure_reason VARCHAR(100), -- INVALID_CODE, RATE_LIMITED, EXPIRED, etc.
                                   device_fingerprint VARCHAR(128),
                                   is_trusted_device BOOLEAN DEFAULT FALSE,
                                   attempted_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- MFA Settings table (tenant-level configuration)
CREATE TABLE mfa_settings (
                              tenant_id UUID PRIMARY KEY REFERENCES tenant(id) ON DELETE CASCADE,
                              is_required BOOLEAN NOT NULL DEFAULT FALSE, -- Force MFA for all users
                              require_for_admin BOOLEAN NOT NULL DEFAULT TRUE, -- Force MFA for admin roles
                              require_for_roles TEXT[], -- Array of roles requiring MFA
                              allow_trusted_devices BOOLEAN NOT NULL DEFAULT TRUE,
                              trusted_device_expiry_days INTEGER DEFAULT 30,
                              max_backup_codes INTEGER NOT NULL DEFAULT 10,
                              rate_limit_attempts INTEGER NOT NULL DEFAULT 5,
                              rate_limit_window_minutes INTEGER NOT NULL DEFAULT 15,
                              lockout_duration_minutes INTEGER NOT NULL DEFAULT 60,
                              qr_code_issuer_name VARCHAR(50) DEFAULT 'PayShield',
                              created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                              updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                              updated_by UUID REFERENCES users(id)
);

-- Create indexes for performance
CREATE INDEX idx_mfa_configuration_tenant ON mfa_configuration(tenant_id);
CREATE INDEX idx_mfa_configuration_status ON mfa_configuration(status);
CREATE INDEX idx_mfa_backup_codes_user ON mfa_backup_codes(user_id);
CREATE INDEX idx_mfa_backup_codes_hash ON mfa_backup_codes(code_hash);
CREATE INDEX idx_mfa_backup_codes_tenant ON mfa_backup_codes(tenant_id);
CREATE INDEX idx_mfa_trusted_devices_user ON mfa_trusted_devices(user_id);
CREATE INDEX idx_mfa_trusted_devices_fingerprint ON mfa_trusted_devices(device_fingerprint);
CREATE INDEX idx_mfa_trusted_devices_expires ON mfa_trusted_devices(expires_at) WHERE expires_at IS NOT NULL;
CREATE INDEX idx_mfa_auth_attempts_user ON mfa_auth_attempts(user_id);
CREATE INDEX idx_mfa_auth_attempts_time ON mfa_auth_attempts(attempted_at DESC);
CREATE INDEX idx_mfa_auth_attempts_ip ON mfa_auth_attempts(ip_address);
CREATE INDEX idx_mfa_auth_attempts_tenant ON mfa_auth_attempts(tenant_id);

-- Add MFA-related columns to the users table
ALTER TABLE users
    ADD COLUMN mfa_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN mfa_enforced BOOLEAN NOT NULL DEFAULT FALSE, -- Admin can force MFA
    ADD COLUMN last_mfa_setup_at TIMESTAMPTZ,
    ADD COLUMN mfa_backup_codes_count INTEGER NOT NULL DEFAULT 0;

-- Insert default MFA settings for existing tenants
INSERT INTO mfa_settings (tenant_id, is_required, require_for_admin, allow_trusted_devices)
SELECT id, FALSE, TRUE, TRUE
FROM tenant
ON CONFLICT (tenant_id) DO NOTHING;

-- Audit triggers for MFA tables
CREATE OR REPLACE FUNCTION update_mfa_updated_at()
    RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trigger_mfa_configuration_updated_at
    BEFORE UPDATE ON mfa_configuration
    FOR EACH ROW
EXECUTE FUNCTION update_mfa_updated_at();

CREATE TRIGGER trigger_mfa_settings_updated_at
    BEFORE UPDATE ON mfa_settings
    FOR EACH ROW
EXECUTE FUNCTION update_mfa_updated_at();

-- Comments for documentation
COMMENT ON TABLE mfa_configuration IS 'Stores TOTP configuration and status for each user';
COMMENT ON TABLE mfa_backup_codes IS 'One-time backup codes for MFA recovery';
COMMENT ON TABLE mfa_trusted_devices IS 'Devices trusted to skip MFA for limited time';
COMMENT ON TABLE mfa_auth_attempts IS 'Audit log of all MFA authentication attempts';
COMMENT ON TABLE mfa_settings IS 'Tenant-level MFA configuration and policies';

COMMENT ON COLUMN mfa_configuration.encrypted_secret IS 'AES-256-GCM encrypted TOTP shared secret';
COMMENT ON COLUMN mfa_configuration.secret_hash IS 'SHA-256 hash of secret for validation';
COMMENT ON COLUMN mfa_configuration.status IS 'PENDING, ENABLED, DISABLED, LOCKED';
COMMENT ON COLUMN mfa_backup_codes.encrypted_code IS 'AES-256-GCM encrypted backup code';
COMMENT ON COLUMN mfa_backup_codes.code_hash IS 'SHA-256 hash for duplicate prevention';
COMMENT ON COLUMN mfa_trusted_devices.device_fingerprint IS 'Unique device identification hash';
COMMENT ON COLUMN mfa_auth_attempts.provided_code IS 'Provided TOTP code (for security analysis)';
COMMENT ON COLUMN mfa_settings.require_for_roles IS 'PostgreSQL array of role names requiring MFA';