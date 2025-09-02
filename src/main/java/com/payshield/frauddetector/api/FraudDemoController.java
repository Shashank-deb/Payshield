package com.payshield.frauddetector.api;

import com.payshield.frauddetector.config.TenantContext;
import com.payshield.frauddetector.domain.DetectionEngine;
import com.payshield.frauddetector.infrastructure.adapters.JpaVendorHistoryRepositoryAdapter;
import com.payshield.frauddetector.infrastructure.jpa.SpringVendorRepository;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.ExampleObject;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.math.BigDecimal;
import java.time.DayOfWeek;
import java.time.OffsetDateTime;
import java.util.*;

/**
 * Demo/Test controller for the fraud detection engine.
 * NOTE: This class assumes DetectionEngine, TenantContext, and the JPA adapter/repository exist in your project.
 */
@RestController
@RequestMapping("/fraud")
@Tag(name = "Fraud Detection Testing", description = "Test and demonstrate fraud detection capabilities")
@SecurityRequirement(name = "Bearer Authentication")
public class FraudDemoController {

    private static final Logger log = LoggerFactory.getLogger(FraudDemoController.class);

    private final DetectionEngine engine = new DetectionEngine();
    private final JpaVendorHistoryRepositoryAdapter vendorRepo;

    public FraudDemoController(SpringVendorRepository springVendorRepo) {
        this.vendorRepo = new JpaVendorHistoryRepositoryAdapter(springVendorRepo);
    }

    // ---------- IBAN VALIDATION ----------

    @PostMapping("/test/iban-validation")
    @Operation(
            summary = "Test IBAN validation",
            description = "Test the ISO 13616 IBAN checksum validation algorithm with real IBAN numbers"
    )
    @ApiResponses({
            @ApiResponse(
                    responseCode = "200",
                    description = "IBAN validation completed",
                    content = @Content(
                            mediaType = "application/json",
                            examples = @ExampleObject(value = """
                {
                  "iban": "GB29NWBK60161331926819",
                  "valid": true,
                  "riskScore": 0,
                  "riskLevel": "LOW",
                  "violations": [],
                  "recommendation": "APPROVE - Minimal risk detected"
                }
                """)
                    )
            )
    })
    public ResponseEntity<?> testIbanValidation(
            @io.swagger.v3.oas.annotations.parameters.RequestBody(
                    description = "IBAN to validate",
                    content = @Content(
                            mediaType = "application/json",
                            examples = {
                                    @ExampleObject(name = "Valid UK IBAN", value = "{\"iban\": \"GB29NWBK60161331926819\"}"),
                                    @ExampleObject(name = "Invalid IBAN", value = "{\"iban\": \"GB00INVALID123456789\"}")
                            }
                    )
            )
            @RequestBody Map<String, String> request
    ) {
        UUID tenantId = TenantContext.getTenantId();
        if (tenantId == null) {
            return ResponseEntity.badRequest().body(Map.of("error", "Missing tenant context"));
        }

        String iban = request.get("iban");
        if (iban == null || iban.isBlank()) {
            return ResponseEntity.badRequest().body(Map.of("error", "Missing 'iban'"));
        }

        log.info("Testing IBAN validation for: {}", iban);

        DetectionEngine.Result result = engine.evaluate(
                tenantId, "Test Vendor", null, iban, null, null,
                Optional.empty(), OffsetDateTime.now(), vendorRepo
        );

        DetectionEngine.RiskAssessment assessment = engine.assessRisk(result);

        Map<String, Object> response = new HashMap<>();
        response.put("iban", iban);
        response.put("valid", !result.getViolations().contains(DetectionEngine.Rule.IBAN_CHECKSUM_INVALID));
        response.put("riskScore", assessment.riskScore);
        response.put("riskLevel", assessment.riskLevel);
        response.put("violations", result.getViolations());
        response.put("recommendation", assessment.recommendation);

        return ResponseEntity.ok(response);
    }

    // ---------- AMOUNT ANALYSIS ----------

    @PostMapping("/test/amount-analysis")
    @Operation(
            summary = "Test amount pattern analysis",
            description = "Analyze invoice amounts for suspicious patterns like round numbers or high-risk thresholds"
    )
    @ApiResponses({
            @ApiResponse(
                    responseCode = "200",
                    description = "Amount analysis completed",
                    content = @Content(
                            mediaType = "application/json",
                            examples = @ExampleObject(value = """
                {
                  "amount": 50000.00,
                  "currency": "USD",
                  "suspiciousRoundAmount": true,
                  "exceedsThreshold": true,
                  "riskScore": 100,
                  "riskLevel": "CRITICAL",
                  "violations": ["AMOUNT_THRESHOLD_EXCEEDED", "SUSPICIOUS_ROUND_AMOUNT"]
                }
                """)
                    )
            )
    })
    public ResponseEntity<?> testAmountAnalysis(
            @io.swagger.v3.oas.annotations.parameters.RequestBody(
                    description = "Amount and currency to analyze",
                    content = @Content(
                            mediaType = "application/json",
                            examples = {
                                    @ExampleObject(name = "High Risk Amount", value = "{\"amount\": \"75000.00\", \"currency\": \"USD\"}"),
                                    @ExampleObject(name = "Suspicious Round Amount", value = "{\"amount\": \"5000.00\", \"currency\": \"EUR\"}"),
                                    @ExampleObject(name = "Normal Amount", value = "{\"amount\": \"1247.83\", \"currency\": \"USD\"}")
                            }
                    )
            )
            @RequestBody Map<String, Object> request
    ) {
        UUID tenantId = TenantContext.getTenantId();
        if (tenantId == null) {
            return ResponseEntity.badRequest().body(Map.of("error", "Missing tenant context"));
        }

        try {
            Object amountRaw = request.get("amount");
            String currency = (String) request.get("currency");
            if (amountRaw == null || currency == null || currency.isBlank()) {
                return ResponseEntity.badRequest().body(Map.of("error", "Missing 'amount' or 'currency'"));
            }

            BigDecimal amount = new BigDecimal(amountRaw.toString());
            log.info("Testing amount analysis for: {} {}", amount, currency);

            DetectionEngine.Result result = engine.evaluate(
                    tenantId, "Test Vendor", null, null, amount, currency,
                    Optional.empty(), OffsetDateTime.now(), vendorRepo
            );

            DetectionEngine.RiskAssessment assessment = engine.assessRisk(result);

            Map<String, Object> response = new HashMap<>();
            response.put("amount", amount);
            response.put("currency", currency);
            response.put("suspiciousRoundAmount",
                    result.getViolations().contains(DetectionEngine.Rule.SUSPICIOUS_ROUND_AMOUNT));
            response.put("exceedsThreshold",
                    result.getViolations().contains(DetectionEngine.Rule.AMOUNT_THRESHOLD_EXCEEDED));
            response.put("riskScore", assessment.riskScore);
            response.put("riskLevel", assessment.riskLevel);
            response.put("violations", result.getViolations());

            return ResponseEntity.ok(response);
        } catch (Exception e) {
            log.error("Error in amount analysis test: {}", e.getMessage());
            return ResponseEntity.badRequest().body(Map.of("error", "Invalid amount format"));
        }
    }

    // ---------- TIMING ANALYSIS ----------

    @PostMapping("/test/timing-analysis")
    @Operation(
            summary = "Test submission timing analysis",
            description = "Analyze submission timing patterns to detect suspicious weekend or late-night submissions"
    )
    @ApiResponses({
            @ApiResponse(
                    responseCode = "200",
                    description = "Timing analysis completed",
                    content = @Content(
                            mediaType = "application/json",
                            examples = @ExampleObject(value = """
                {
                  "submissionTime": "2024-09-01T02:30:00Z",
                  "dayOfWeek": "SUNDAY",
                  "hourOfDay": 2,
                  "isWeekend": true,
                  "isLateNight": true,
                  "flaggedForTiming": true,
                  "riskScore": 15,
                  "violations": ["WEEKEND_SUBMISSION"]
                }
                """)
                    )
            )
    })
    public ResponseEntity<?> testTimingAnalysis(
            @io.swagger.v3.oas.annotations.parameters.RequestBody(
                    description = "Optional datetime to test (uses current time if not provided)",
                    content = @Content(
                            mediaType = "application/json",
                            examples = {
                                    @ExampleObject(name = "Weekend Submission", value = "{\"datetime\": \"2024-09-01T02:30:00Z\"}"),
                                    @ExampleObject(name = "Business Hours", value = "{\"datetime\": \"2024-09-03T14:30:00Z\"}"),
                                    @ExampleObject(name = "Current Time", value = "{}")
                            }
                    )
            )
            @RequestBody(required = false) Map<String, String> request
    ) {
        UUID tenantId = TenantContext.getTenantId();
        if (tenantId == null) {
            return ResponseEntity.badRequest().body(Map.of("error", "Missing tenant context"));
        }

        OffsetDateTime testTime = OffsetDateTime.now();
        if (request != null && request.containsKey("datetime") && request.get("datetime") != null) {
            try {
                testTime = OffsetDateTime.parse(request.get("datetime"));
            } catch (Exception e) {
                log.warn("Invalid datetime format, using current time: {}", e.getMessage());
            }
        }

        log.info("Testing timing analysis for: {}", testTime);

        DetectionEngine.Result result = engine.evaluate(
                tenantId, "Test Vendor", null, null, null, null,
                Optional.empty(), testTime, vendorRepo
        );

        DayOfWeek dayOfWeek = testTime.getDayOfWeek();
        int hourOfDay = testTime.getHour();
        boolean isWeekend = (dayOfWeek == DayOfWeek.SATURDAY || dayOfWeek == DayOfWeek.SUNDAY);
        boolean isLateNight = hourOfDay >= 0 && hourOfDay <= 5;

        Map<String, Object> response = new HashMap<>();
        response.put("submissionTime", testTime);
        response.put("dayOfWeek", dayOfWeek);
        response.put("hourOfDay", hourOfDay);
        response.put("isWeekend", isWeekend);
        response.put("isLateNight", isLateNight);
        response.put("flaggedForTiming", result.getViolations().contains(DetectionEngine.Rule.WEEKEND_SUBMISSION));
        response.put("riskScore", engine.assessRisk(result).riskScore);
        response.put("violations", result.getViolations());

        return ResponseEntity.ok(response);
    }

    // ---------- COMPREHENSIVE ANALYSIS ----------

    @PostMapping("/test/comprehensive")
    @Operation(
            summary = "Run comprehensive fraud analysis",
            description = "Test all fraud detection rules together with a complete invoice scenario"
    )
    @ApiResponses({
            @ApiResponse(
                    responseCode = "200",
                    description = "Comprehensive analysis completed",
                    content = @Content(
                            mediaType = "application/json",
                            examples = @ExampleObject(value = """
                {
                  "input": {
                    "vendorName": "Suspicious Corp LLC",
                    "iban": "US00INVALID123456789",
                    "amount": "25000.00",
                    "currency": "USD",
                    "senderDomain": "tempmail.com"
                  },
                  "analysis": {
                    "flagged": true,
                    "riskScore": 105,
                    "riskLevel": "CRITICAL",
                    "recommendation": "REJECT - High fraud probability",
                    "violations": ["IBAN_CHECKSUM_INVALID", "SENDER_MISMATCH", "SUSPICIOUS_ROUND_AMOUNT"]
                  },
                  "details": {
                    "ibanValid": false,
                    "amountSuspicious": true,
                    "timingSuspicious": false,
                    "domainSuspicious": true
                  }
                }
                """)
                    )
            )
    })
    public ResponseEntity<?> testComprehensiveAnalysis(
            @io.swagger.v3.oas.annotations.parameters.RequestBody(
                    description = "Complete invoice data for fraud analysis",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = ComprehensiveTestRequest.class),
                            examples = {
                                    @ExampleObject(
                                            name = "High Risk Scenario",
                                            value = """
                        {
                          "vendorName": "Suspicious Corp LLC",
                          "iban": "US00INVALID123456789",
                          "amount": "75000.00",
                          "currency": "USD",
                          "senderDomain": "tempmail.com"
                        }
                        """
                                    ),
                                    @ExampleObject(
                                            name = "Clean Transaction",
                                            value = """
                        {
                          "vendorName": "Acme Corporation Ltd",
                          "iban": "GB29NWBK60161331926819",
                          "amount": "1247.83",
                          "currency": "GBP",
                          "senderDomain": "acme.com"
                        }
                        """
                                    )
                            }
                    )
            )
            @RequestBody Map<String, Object> request
    ) {
        UUID tenantId = TenantContext.getTenantId();
        if (tenantId == null) {
            return ResponseEntity.badRequest().body(Map.of("error", "Missing tenant context"));
        }

        try {
            String vendorName = (String) request.get("vendorName");
            String iban = (String) request.get("iban");
            BigDecimal amount = request.containsKey("amount") && request.get("amount") != null
                    ? new BigDecimal(request.get("amount").toString()) : null;
            String currency = (String) request.get("currency");
            String senderDomain = (String) request.get("senderDomain");

            log.info("Running comprehensive fraud analysis - vendor: {}, amount: {} {}",
                    vendorName, amount, currency);

            DetectionEngine.Result result = engine.evaluate(
                    tenantId, vendorName, null, iban, amount, currency,
                    Optional.ofNullable(senderDomain), OffsetDateTime.now(), vendorRepo
            );

            DetectionEngine.RiskAssessment assessment = engine.assessRisk(result);

            Map<String, Object> analysisResult = new HashMap<>();
            analysisResult.put("flagged", result.flagged());
            analysisResult.put("riskScore", assessment.riskScore);
            analysisResult.put("riskLevel", assessment.riskLevel);
            analysisResult.put("recommendation", assessment.recommendation);
            analysisResult.put("violations", result.getViolations());

            Map<String, Object> detailsResult = new HashMap<>();
            detailsResult.put("ibanValid", !result.getViolations().contains(DetectionEngine.Rule.IBAN_CHECKSUM_INVALID));
            detailsResult.put("amountSuspicious", result.getViolations().contains(DetectionEngine.Rule.SUSPICIOUS_ROUND_AMOUNT));
            detailsResult.put("timingSuspicious", result.getViolations().contains(DetectionEngine.Rule.WEEKEND_SUBMISSION));
            detailsResult.put("domainSuspicious", result.getViolations().contains(DetectionEngine.Rule.SENDER_MISMATCH));

            Map<String, Object> response = new HashMap<>();
            response.put("input", request);
            response.put("analysis", analysisResult);
            response.put("details", detailsResult);

            return ResponseEntity.ok(response);
        } catch (Exception e) {
            log.error("Error in comprehensive fraud analysis: {}", e.getMessage(), e);
            return ResponseEntity.badRequest().body(Map.of(
                    "error", "Analysis failed",
                    "message", e.getMessage()
            ));
        }
    }

    // ---------- DOMAIN VALIDATION ----------

    @PostMapping("/test/domain-validation")
    @Operation(
            summary = "Test sender domain validation",
            description = "Test email domain reputation checking for suspicious or temporary email services"
    )
    @ApiResponses({
            @ApiResponse(
                    responseCode = "200",
                    description = "Domain validation completed",
                    content = @Content(
                            mediaType = "application/json",
                            examples = @ExampleObject(value = """
                {
                  "domain": "tempmail.com",
                  "suspicious": true,
                  "reason": "Known temporary email service",
                  "riskScore": 30,
                  "violations": ["SENDER_MISMATCH"]
                }
                """)
                    )
            )
    })
    public ResponseEntity<?> testDomainValidation(
            @io.swagger.v3.oas.annotations.parameters.RequestBody(
                    description = "Email domain to validate",
                    content = @Content(
                            mediaType = "application/json",
                            examples = {
                                    @ExampleObject(name = "Suspicious Domain", value = "{\"domain\": \"tempmail.com\"}"),
                                    @ExampleObject(name = "Legitimate Domain", value = "{\"domain\": \"microsoft.com\"}")
                            }
                    )
            )
            @RequestBody Map<String, String> request
    ) {
        UUID tenantId = TenantContext.getTenantId();
        if (tenantId == null) {
            return ResponseEntity.badRequest().body(Map.of("error", "Missing tenant context"));
        }

        String domain = request.get("domain");
        if (domain == null || domain.isBlank()) {
            return ResponseEntity.badRequest().body(Map.of("error", "Missing 'domain'"));
        }

        log.info("Testing domain validation for: {}", domain);

        DetectionEngine.Result result = engine.evaluate(
                tenantId, "Test Vendor", null, null, null, null,
                Optional.of(domain), OffsetDateTime.now(), vendorRepo
        );

        DetectionEngine.RiskAssessment assessment = engine.assessRisk(result);
        boolean suspicious = result.getViolations().contains(DetectionEngine.Rule.SENDER_MISMATCH);

        Map<String, Object> response = new HashMap<>();
        response.put("domain", domain);
        response.put("suspicious", suspicious);
        response.put("reason", suspicious
                ? "Suspicious or temporary email service detected"
                : "Domain appears legitimate");
        response.put("riskScore", assessment.riskScore);
        response.put("violations", result.getViolations());

        return ResponseEntity.ok(response);
    }

    // ---------- RULES ----------

    @GetMapping("/rules")
    @Operation(
            summary = "Get all fraud detection rules",
            description = "Returns comprehensive information about all fraud detection rules, risk scoring, and thresholds"
    )
    @ApiResponses({
            @ApiResponse(
                    responseCode = "200",
                    description = "Fraud rules retrieved successfully",
                    content = @Content(
                            mediaType = "application/json",
                            examples = @ExampleObject(value = """
                {
                  "availableRules": {
                    "NEW_ACCOUNT": "New vendor with bank account details",
                    "CHANGED_ACCOUNT": "Existing vendor changed bank account",
                    "INVALID_FORMAT": "Invalid bank account format",
                    "SENDER_MISMATCH": "Email domain doesn't match expected"
                  },
                  "riskScoring": {
                    "LOW": "0-24 points - Minimal risk",
                    "MEDIUM": "25-49 points - Some concerns",
                    "HIGH": "50-79 points - Manual review required",
                    "CRITICAL": "80+ points - High fraud probability"
                  },
                  "thresholds": {
                    "flagThreshold": 50,
                    "highAmountThreshold": "$50,000",
                    "automaticReject": 80
                  }
                }
                """)
                    )
            )
    })
    public ResponseEntity<?> getRules() {
        Map<String, String> availableRules = new HashMap<>();
        availableRules.put("NEW_ACCOUNT", "New vendor with bank account details");
        availableRules.put("CHANGED_ACCOUNT", "Existing vendor changed bank account");
        availableRules.put("INVALID_FORMAT", "Invalid bank account format");
        availableRules.put("SENDER_MISMATCH", "Email domain doesn't match expected");
        availableRules.put("IBAN_CHECKSUM_INVALID", "IBAN fails ISO 13616 checksum validation");
        availableRules.put("VELOCITY_ANOMALY", "Too many invoices in short time period");
        availableRules.put("AMOUNT_OUTLIER", "Amount unusual for vendor's historical pattern");
        availableRules.put("WEEKEND_SUBMISSION", "Submitted during weekend or late night");
        availableRules.put("DUPLICATE_BANK_ACCOUNT", "Bank account used by multiple vendors");
        availableRules.put("COUNTRY_MISMATCH", "IBAN country doesn't match vendor location");
        availableRules.put("AMOUNT_THRESHOLD_EXCEEDED", "Amount exceeds high-risk threshold ($50,000)");
        availableRules.put("SUSPICIOUS_ROUND_AMOUNT", "Exactly round amount (often used in fraud)");

        Map<String, String> riskScoring = new HashMap<>();
        riskScoring.put("LOW", "0-24 points - Minimal risk");
        riskScoring.put("MEDIUM", "25-49 points - Some concerns");
        riskScoring.put("HIGH", "50-79 points - Manual review required");
        riskScoring.put("CRITICAL", "80+ points - High fraud probability");

        Map<String, Object> thresholds = new HashMap<>();
        thresholds.put("flagThreshold", 50);
        thresholds.put("highAmountThreshold", "$50,000");
        thresholds.put("automaticReject", 80);

        Map<String, Object> response = new HashMap<>();
        response.put("availableRules", availableRules);
        response.put("riskScoring", riskScoring);
        response.put("thresholds", thresholds);

        return ResponseEntity.ok(response);
    }

    // ---------- SCORING DETAILS ----------

    @GetMapping("/scoring")
    @Operation(
            summary = "Get detailed risk scoring information",
            description = "Returns detailed information about how risk scores are calculated for each rule type"
    )
    @ApiResponses({
            @ApiResponse(
                    responseCode = "200",
                    description = "Risk scoring details retrieved successfully",
                    content = @Content(
                            mediaType = "application/json",
                            examples = @ExampleObject(value = """
                {
                  "ruleScores": {
                    "NEW_ACCOUNT": 25,
                    "CHANGED_ACCOUNT": 35,
                    "IBAN_CHECKSUM_INVALID": 50,
                    "AMOUNT_THRESHOLD_EXCEEDED": 80
                  },
                  "flaggingLogic": {
                    "automaticFlag": "Risk score >= 50 OR critical violations",
                    "criticalViolations": ["IBAN_CHECKSUM_INVALID", "DUPLICATE_BANK_ACCOUNT", "AMOUNT_THRESHOLD_EXCEEDED"],
                    "scoringModel": "Additive - multiple violations compound the risk score"
                  }
                }
                """)
                    )
            )
    })
    public ResponseEntity<?> getScoring() {
        Map<String, Integer> ruleScores = new HashMap<>();
        ruleScores.put("NEW_ACCOUNT", 25);
        ruleScores.put("CHANGED_ACCOUNT", 35);
        ruleScores.put("IBAN_CHECKSUM_INVALID", 50);
        ruleScores.put("DUPLICATE_BANK_ACCOUNT", 60);
        ruleScores.put("SENDER_MISMATCH", 30);
        ruleScores.put("VELOCITY_ANOMALY", 40);
        ruleScores.put("AMOUNT_OUTLIER", 45);
        ruleScores.put("WEEKEND_SUBMISSION", 15);
        ruleScores.put("COUNTRY_MISMATCH", 25);
        ruleScores.put("AMOUNT_THRESHOLD_EXCEEDED", 80);
        ruleScores.put("SUSPICIOUS_ROUND_AMOUNT", 20);
        ruleScores.put("INVALID_FORMAT", 30);

        Map<String, Object> flaggingLogic = new HashMap<>();
        flaggingLogic.put("automaticFlag", "Risk score >= 50 OR critical violations");
        flaggingLogic.put("criticalViolations",
                new String[]{"IBAN_CHECKSUM_INVALID", "DUPLICATE_BANK_ACCOUNT", "AMOUNT_THRESHOLD_EXCEEDED"});
        flaggingLogic.put("scoringModel", "Additive - multiple violations compound the risk score");

        Map<String, Object> response = new HashMap<>();
        response.put("ruleScores", ruleScores);
        response.put("flaggingLogic", flaggingLogic);

        return ResponseEntity.ok(response);
    }

    // ---------- EXAMPLES ----------

    @GetMapping("/examples")
    @Operation(
            summary = "Get fraud detection examples",
            description = "Returns example scenarios showing how different rule combinations result in different risk levels"
    )
    @ApiResponses({
            @ApiResponse(
                    responseCode = "200",
                    description = "Examples retrieved successfully",
                    content = @Content(
                            mediaType = "application/json",
                            examples = @ExampleObject(value = """
                {
                  "lowRiskExample": {
                    "scenario": "Known vendor, same bank account, business hours",
                    "triggeredRules": [],
                    "riskScore": 0,
                    "outcome": "APPROVED"
                  },
                  "criticalRiskExample": {
                    "scenario": "Invalid IBAN + high amount + suspicious domain",
                    "triggeredRules": ["IBAN_CHECKSUM_INVALID", "AMOUNT_THRESHOLD_EXCEEDED", "SENDER_MISMATCH"],
                    "riskScore": 160,
                    "outcome": "REJECT"
                  }
                }
                """)
                    )
            )
    })
    public ResponseEntity<?> getExamples() {
        Map<String, Object> response = new HashMap<>();

        Map<String, Object> lowRisk = new HashMap<>();
        lowRisk.put("scenario", "Known vendor, same bank account, business hours");
        lowRisk.put("triggeredRules", new String[]{});
        lowRisk.put("riskScore", 0);
        lowRisk.put("outcome", "APPROVED");

        Map<String, Object> mediumRisk = new HashMap<>();
        mediumRisk.put("scenario", "New vendor account with valid details");
        mediumRisk.put("triggeredRules", new String[]{"NEW_ACCOUNT"});
        mediumRisk.put("riskScore", 25);
        mediumRisk.put("outcome", "ENHANCED_VERIFICATION");

        Map<String, Object> highRisk = new HashMap<>();
        highRisk.put("scenario", "Changed bank account + weekend submission");
        highRisk.put("triggeredRules", new String[]{"CHANGED_ACCOUNT", "WEEKEND_SUBMISSION"});
        highRisk.put("riskScore", 50);
        highRisk.put("outcome", "MANUAL_REVIEW");

        Map<String, Object> criticalRisk = new HashMap<>();
        criticalRisk.put("scenario", "Invalid IBAN checksum + high amount + suspicious domain");
        criticalRisk.put("triggeredRules", new String[]{"IBAN_CHECKSUM_INVALID", "AMOUNT_THRESHOLD_EXCEEDED", "SENDER_MISMATCH"});
        criticalRisk.put("riskScore", 160);
        criticalRisk.put("outcome", "REJECT");

        response.put("lowRiskExample", lowRisk);
        response.put("mediumRiskExample", mediumRisk);
        response.put("highRiskExample", highRisk);
        response.put("criticalRiskExample", criticalRisk);

        return ResponseEntity.ok(response);
    }

    // ---------- BATCH TESTING ----------

    @PostMapping("/test/batch")
    @Operation(
            summary = "Test multiple scenarios at once",
            description = "Run fraud detection on multiple test scenarios to compare results"
    )
    @ApiResponses({
            @ApiResponse(
                    responseCode = "200",
                    description = "Batch testing completed",
                    content = @Content(
                            mediaType = "application/json",
                            examples = @ExampleObject(value = """
                {
                  "results": [
                    {
                      "scenario": "Clean Transaction",
                      "riskLevel": "LOW",
                      "riskScore": 0,
                      "flagged": false
                    },
                    {
                      "scenario": "Suspicious Transaction",
                      "riskLevel": "CRITICAL",
                      "riskScore": 130,
                      "flagged": true
                    }
                  ],
                  "summary": {
                    "totalTests": 2,
                    "flaggedCount": 1,
                    "averageRiskScore": 65.0,
                    "flaggedPercentage": 50.0
                  }
                }
                """)
                    )
            )
    })
    public ResponseEntity<?> testBatchScenarios(
            @io.swagger.v3.oas.annotations.parameters.RequestBody(
                    description = "Array of test scenarios to analyze",
                    content = @Content(
                            mediaType = "application/json",
                            examples = @ExampleObject(value = """
                {
                  "scenarios": [
                    {
                      "name": "Clean Transaction",
                      "vendorName": "Acme Corp Ltd",
                      "iban": "GB29NWBK60161331926819",
                      "amount": "1247.83",
                      "currency": "GBP"
                    },
                    {
                      "name": "Suspicious Transaction",
                      "vendorName": "Unknown Vendor",
                      "iban": "INVALID123456",
                      "amount": "75000.00",
                      "currency": "USD",
                      "senderDomain": "tempmail.com"
                    }
                  ]
                }
                """)
                    )
            )
            @RequestBody Map<String, Object> request
    ) {
        UUID tenantId = TenantContext.getTenantId();
        if (tenantId == null) {
            return ResponseEntity.badRequest().body(Map.of("error", "Missing tenant context"));
        }

        try {
            @SuppressWarnings("unchecked")
            List<Map<String, Object>> scenarios =
                    (List<Map<String, Object>>) request.get("scenarios");

            if (scenarios == null || scenarios.isEmpty()) {
                return ResponseEntity.badRequest().body(Map.of("error", "No scenarios provided"));
            }

            List<Map<String, Object>> results = new ArrayList<>();
            int totalRiskScore = 0;
            int flaggedCount = 0;

            for (Map<String, Object> scenario : scenarios) {
                try {
                    String name = (String) scenario.get("name");
                    String vendorName = (String) scenario.get("vendorName");
                    String iban = (String) scenario.get("iban");
                    BigDecimal amount = scenario.containsKey("amount") && scenario.get("amount") != null
                            ? new BigDecimal(scenario.get("amount").toString()) : null;
                    String currency = (String) scenario.get("currency");
                    String senderDomain = (String) scenario.get("senderDomain");

                    DetectionEngine.Result result = engine.evaluate(
                            tenantId, vendorName, null, iban, amount, currency,
                            Optional.ofNullable(senderDomain), OffsetDateTime.now(), vendorRepo
                    );

                    DetectionEngine.RiskAssessment assessment = engine.assessRisk(result);

                    Map<String, Object> scenarioResult = new HashMap<>();
                    scenarioResult.put("scenario", (name != null && !name.isBlank()) ? name : "Unnamed Scenario");
                    scenarioResult.put("riskLevel", assessment.riskLevel);
                    scenarioResult.put("riskScore", assessment.riskScore);
                    scenarioResult.put("flagged", result.flagged());
                    scenarioResult.put("violations", result.getViolations());
                    scenarioResult.put("recommendation", assessment.recommendation);

                    results.add(scenarioResult);
                    totalRiskScore += assessment.riskScore;
                    if (result.flagged()) {
                        flaggedCount++;
                    }
                } catch (Exception e) {
                    log.error("Error processing scenario: {}", e.getMessage());
                    Map<String, Object> errorResult = new HashMap<>();
                    errorResult.put("scenario", scenario.get("name"));
                    errorResult.put("error", e.getMessage());
                    results.add(errorResult);
                }
            }

            int total = scenarios.size();
            double averageRiskScore = total > 0 ? ((double) totalRiskScore) / total : 0.0;
            double flaggedPercentage = total > 0 ? (flaggedCount * 100.0 / total) : 0.0;

            Map<String, Object> summary = new HashMap<>();
            summary.put("totalTests", total);
            summary.put("flaggedCount", flaggedCount);
            summary.put("averageRiskScore", averageRiskScore);
            summary.put("flaggedPercentage", flaggedPercentage);

            Map<String, Object> response = new HashMap<>();
            response.put("results", results);
            response.put("summary", summary);

            return ResponseEntity.ok(response);
        } catch (Exception e) {
            log.error("Error in batch fraud testing: {}", e.getMessage(), e);
            return ResponseEntity.badRequest().body(Map.of(
                    "error", "Batch testing failed",
                    "message", e.getMessage()
            ));
        }
    }

    // ---------- DTOs FOR OPENAPI ----------

    @Schema(description = "Request for comprehensive fraud analysis testing")
    public static class ComprehensiveTestRequest {
        @Schema(description = "Vendor name", example = "Acme Corporation Ltd")
        public String vendorName;

        @Schema(description = "IBAN bank account number", example = "GB29NWBK60161331926819")
        public String iban;

        @Schema(description = "Invoice amount", example = "1500.50")
        public String amount;

        @Schema(description = "Currency code (3 letters)", example = "USD")
        public String currency;

        @Schema(description = "Email sender domain", example = "acme.com")
        public String senderDomain;
    }

    @Schema(description = "Request for batch fraud testing")
    public static class BatchTestRequest {
        @Schema(description = "Array of test scenarios")
        public List<TestScenario> scenarios;
    }

    @Schema(description = "Individual test scenario")
    public static class TestScenario {
        @Schema(description = "Scenario name", example = "Clean Transaction")
        public String name;

        @Schema(description = "Vendor name", example = "Acme Corp")
        public String vendorName;

        @Schema(description = "IBAN", example = "GB29NWBK60161331926819")
        public String iban;

        @Schema(description = "Amount", example = "1500.00")
        public String amount;

        @Schema(description = "Currency", example = "USD")
        public String currency;

        @Schema(description = "Sender domain", example = "acme.com")
        public String senderDomain;
    }
}
