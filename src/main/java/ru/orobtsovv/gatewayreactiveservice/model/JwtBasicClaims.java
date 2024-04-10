package ru.orobtsovv.gatewayreactiveservice.model;

import ru.orobtsovv.gatewayreactiveservice.security.BasicPrincipal;
import lombok.Data;
import lombok.experimental.Accessors;

import java.util.List;

@Data
@Accessors(chain = true)
public class JwtBasicClaims implements BasicPrincipal {
    private int userid;
    private List<Role> roles;
}
