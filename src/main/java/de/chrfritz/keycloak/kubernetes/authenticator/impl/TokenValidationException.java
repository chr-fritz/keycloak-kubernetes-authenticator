package de.chrfritz.keycloak.kubernetes.authenticator.impl;

/**
 * A runtime exception that indicates that the validation of the received client assertation jwt was not successful.
 */
public class TokenValidationException extends RuntimeException {

    public TokenValidationException(String message) {
        super(message);
    }

    public TokenValidationException(String message, Throwable cause) {
        super(message, cause);
    }
}
