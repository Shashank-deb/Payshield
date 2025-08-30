package com.payshield.frauddetector.api;

import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.*;

@RestController
@RequestMapping("/debug")
public class DebugController {

    private static final Logger log = LoggerFactory.getLogger(DebugController.class);

    @PostMapping("/test")
    public ResponseEntity<?> testPost(@RequestBody(required = false) Map<String, Object> body,
                                     HttpServletRequest request) {
        log.info("POST /debug/test called");
        
        // Log all headers
        Enumeration<String> headerNames = request.getHeaderNames();
        Map<String, String> headers = new HashMap<>();
        while (headerNames.hasMoreElements()) {
            String headerName = headerNames.nextElement();
            headers.put(headerName, request.getHeader(headerName));
        }
        
        log.info("Request headers: {}", headers);
        log.info("Request body: {}", body);
        
        return ResponseEntity.ok(Map.of(
                "message", "POST request successful",
                "timestamp", new Date(),
                "receivedBody", body != null ? body : Map.of(),
                "receivedHeaders", headers
        ));
    }

    @GetMapping("/test")
    public ResponseEntity<?> testGet() {
        log.info("GET /debug/test called");
        return ResponseEntity.ok(Map.of(
                "message", "GET request successful",
                "timestamp", new Date()
        ));
    }

    @PostMapping("/simple")
    public ResponseEntity<?> simplePost() {
        log.info("POST /debug/simple called");
        return ResponseEntity.ok(Map.of("status", "ok"));
    }

    @PostMapping("/echo")
    public ResponseEntity<?> echo(@RequestBody String body) {
        log.info("POST /debug/echo called with body: {}", body);
        return ResponseEntity.ok(Map.of(
                "received", body,
                "length", body.length(),
                "timestamp", new Date()
        ));
    }
}