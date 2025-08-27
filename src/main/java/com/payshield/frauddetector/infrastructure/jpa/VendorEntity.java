package com.payshield.frauddetector.infrastructure.jpa;

import jakarta.persistence.*;
import java.util.UUID;

@Entity
@Table(name = "vendor")
public class VendorEntity {

    @Id
    private UUID id;

    @Column(name = "tenant_id", nullable = false)
    private UUID tenantId;

    @Column(nullable = false)
    private String name;

    @Column(name = "email_domain")
    private String emailDomain;

    @Column(name = "current_bank_last4")
    private String currentBankLast4;

    public UUID getId() { return id; }
    public void setId(UUID id) { this.id = id; }

    public UUID getTenantId() { return tenantId; }
    public void setTenantId(UUID tenantId) { this.tenantId = tenantId; }

    public String getName() { return name; }
    public void setName(String name) { this.name = name; }

    public String getEmailDomain() { return emailDomain; }
    public void setEmailDomain(String emailDomain) { this.emailDomain = emailDomain; }

    public String getCurrentBankLast4() { return currentBankLast4; }
    public void setCurrentBankLast4(String currentBankLast4) { this.currentBankLast4 = currentBankLast4; }
}
