package com.payshield.frauddetector.config;

import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.Enumeration;

@Component
@Order(1) // Run this filter first
public class RequestLoggingFilter implements Filter {

    private static final Logger log = LoggerFactory.getLogger(RequestLoggingFilter.class);

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) 
            throws IOException, ServletException {
        
        HttpServletRequest httpRequest = (HttpServletRequest) request;
        HttpServletResponse httpResponse = (HttpServletResponse) response;
        
        String method = httpRequest.getMethod();
        String uri = httpRequest.getRequestURI();
        String queryString = httpRequest.getQueryString();
        
        log.info("=== INCOMING REQUEST: {} {} {}", method, uri, queryString != null ? "?" + queryString : "");
        
        // Log headers for debugging
        Enumeration<String> headerNames = httpRequest.getHeaderNames();
        while (headerNames.hasMoreElements()) {
            String headerName = headerNames.nextElement();
            String headerValue = headerName.toLowerCase().contains("authorization") ? 
                "Bearer ***" : httpRequest.getHeader(headerName);
            log.info("REQUEST HEADER: {} = {}", headerName, headerValue);
        }
        
        long startTime = System.currentTimeMillis();
        
        try {
            // Continue with the filter chain
            log.info("REQUEST: Processing {} {}", method, uri);
            chain.doFilter(request, response);
            log.info("REQUEST: Completed {} {} - Status: {} - Time: {}ms", 
                    method, uri, httpResponse.getStatus(), System.currentTimeMillis() - startTime);
        } catch (Exception e) {
            log.error("REQUEST: Error processing {} {}: {}", method, uri, e.getMessage(), e);
            throw e;
        }
    }
}