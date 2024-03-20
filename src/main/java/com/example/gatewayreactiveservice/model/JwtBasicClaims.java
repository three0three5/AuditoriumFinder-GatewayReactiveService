package com.example.gatewayreactiveservice.model;

import com.example.gatewayreactiveservice.security.BasicPrincipal;
import lombok.Data;
import lombok.experimental.Accessors;

import java.util.List;

@Data
@Accessors(chain = true)
public class JwtBasicClaims implements BasicPrincipal {
    private String username;
    private int userid;
    private List<Role> roles;
}
