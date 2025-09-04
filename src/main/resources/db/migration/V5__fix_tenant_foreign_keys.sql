-- Create: src/main/resources/db/migration/V5__fix_tenant_foreign_keys.sql

-- First, add the missing foreign key constraint properly
-- The current schema has references but may be missing the actual constraint

-- Check if we need to add the foreign key constraint to vendor table
-- (This should already exist from V1, but let's ensure it's there)
ALTER TABLE vendor
    ADD CONSTRAINT fk_vendor_tenant
        FOREIGN KEY (tenant_id) REFERENCES tenant(id)
            ON DELETE CASCADE;

-- Same for invoice table
ALTER TABLE invoice
    ADD CONSTRAINT fk_invoice_tenant
        FOREIGN KEY (tenant_id) REFERENCES tenant(id)
            ON DELETE CASCADE;

-- Same for case_workflow table
ALTER TABLE case_workflow
    ADD CONSTRAINT fk_case_tenant
        FOREIGN KEY (tenant_id) REFERENCES tenant(id)
            ON DELETE CASCADE;

-- Same for users table (from V3)
ALTER TABLE users
    ADD CONSTRAINT fk_users_tenant
        FOREIGN KEY (tenant_id) REFERENCES tenant(id)
            ON DELETE CASCADE;

-- Add indexes for better performance on tenant-based queries
CREATE INDEX IF NOT EXISTS idx_vendor_tenant ON vendor(tenant_id);
CREATE INDEX IF NOT EXISTS idx_invoice_tenant ON invoice(tenant_id);
CREATE INDEX IF NOT EXISTS idx_case_tenant ON case_workflow(tenant_id);
CREATE INDEX IF NOT EXISTS idx_users_tenant ON users(tenant_id);

-- Insert the default tenant that the bootstrap process expects
INSERT INTO tenant (id, name)
VALUES ('00000000-0000-0000-0000-000000000001'::uuid, 'Default Tenant')
ON CONFLICT (id) DO NOTHING;