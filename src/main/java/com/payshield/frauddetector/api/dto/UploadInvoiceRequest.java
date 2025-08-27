package com.payshield.frauddetector.api.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public class UploadInvoiceRequest {
  @NotBlank public String vendorName;
  @Size(min=3,max=3) public String currency;
}
