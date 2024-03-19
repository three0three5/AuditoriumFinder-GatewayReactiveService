package com.example.gatewayreactiveservice.dto;

import lombok.Data;

@Data
public class RsaPublicKeyResponse {
    private String kty;
    private String n;
    private String e;
}
