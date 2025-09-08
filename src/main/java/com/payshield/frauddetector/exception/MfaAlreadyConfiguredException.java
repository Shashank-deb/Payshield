package com.payshield.frauddetector.exception;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;

import java.util.HashMap;
import java.util.Map;

/**
 * Exception thrown when an attempt is made to configure MFA for a user who already has it enabled.
 */
public class MfaAlreadyConfiguredException extends RuntimeException {
    
    /**
     * Constructs a new MFA already configured exception with null as its detail message.
     */
    public MfaAlreadyConfiguredException() {
        super();
    }

    /**
     * Constructs a new MFA already configured exception with the specified detail message.
     *
     * @param message the detail message
     */
    public MfaAlreadyConfiguredException(String message) {
        super(message);
    }

    /**
     * Constructs a new MFA already configured exception with the specified detail message and cause.
     *
     * @param message the detail message
     * @param cause the cause (which is saved for later retrieval)
     */
    public MfaAlreadyConfiguredException(String message, Throwable cause) {
        super(message, cause);
    }

    /**
     * Constructs a new MFA already configured exception with the specified cause.
     *
     * @param cause the cause (which is saved for later retrieval)
     */
    public MfaAlreadyConfiguredException(Throwable cause) {
        super(cause);
    }
}
