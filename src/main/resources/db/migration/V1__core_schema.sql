create table if not exists tenant (
                                      id uuid primary key,
                                      name text not null unique
);

create table if not exists vendor (
                                      id uuid primary key,
                                      tenant_id uuid not null references tenant(id),
                                      name text not null,
                                      email_domain text,
                                      current_bank_last4 text,
                                      unique(tenant_id, name)
);

create table if not exists invoice (
                                       id uuid primary key,
                                       tenant_id uuid not null references tenant(id),
                                       vendor_id uuid not null references vendor(id),
                                       received_at timestamptz not null default now(),
                                       amount numeric(18,2),
                                       currency char(3),
                                       bank_iban text,
                                       bank_swift text,
                                       bank_last4 text,
                                       source_message_id text,
                                       file_sha256 text
);

create table if not exists case_workflow (
                                             id uuid primary key,
                                             tenant_id uuid not null references tenant(id),
                                             invoice_id uuid not null references invoice(id),
                                             state text not null,             -- NEW, FLAGGED, APPROVED, REJECTED, ESCALATED
                                             created_at timestamptz not null default now()
);

create table if not exists audit_log (
                                         id bigserial primary key,
                                         tenant_id uuid not null,
                                         actor text not null,
                                         action text not null,
                                         entity_type text not null,
                                         entity_id text not null,
                                         at timestamptz not null default now(),
                                         hmac_chain text not null
);

create table if not exists outbox (
                                      event_id uuid primary key,
                                      tenant_id uuid not null,
                                      type text not null,
                                      payload_json jsonb not null,
                                      occurred_at timestamptz not null default now(),
                                      processed_at timestamptz
);
