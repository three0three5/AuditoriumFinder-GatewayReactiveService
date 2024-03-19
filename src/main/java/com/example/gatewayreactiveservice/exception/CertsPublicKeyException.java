package com.example.gatewayreactiveservice.exception;

public class CertsPublicKeyException extends RuntimeException {
    public CertsPublicKeyException(Exception e) {
        super(e);
    }

    public CertsPublicKeyException(String e) {
        super(e);
    }
}
