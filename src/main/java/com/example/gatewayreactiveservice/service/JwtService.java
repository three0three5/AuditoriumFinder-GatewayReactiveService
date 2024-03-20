package com.example.gatewayreactiveservice.service;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.example.gatewayreactiveservice.client.AuthClient;
import com.example.gatewayreactiveservice.model.JwtBasicClaims;
import com.example.gatewayreactiveservice.exception.CertsPublicKeyException;
import com.example.gatewayreactiveservice.model.Role;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.util.List;

import static com.example.gatewayreactiveservice.utils.ExceptionConstants.CERTS_UNAVAILABLE;

@Service
@RequiredArgsConstructor
public class JwtService {
    private final AuthClient authClient;

    public Mono<DecodedJWT> verify(String token) {
        return authClient
                .getPublicSignatureKey()
                .switchIfEmpty(Mono.error(new CertsPublicKeyException(CERTS_UNAVAILABLE)))
                .map(publicKey -> {
                    Algorithm algorithm = Algorithm.RSA256(publicKey);
                    JWTVerifier verifier = JWT.require(algorithm)
                            .withIssuer("auth0")
                            .build();
                    return verifier.verify(token);
                });
    }

    public JwtBasicClaims getBasicClaims(DecodedJWT jwt) {
        String username = jwt.getClaim("username").asString();
        int userid = jwt.getClaim("userid").asInt();
        List<Role> roles = jwt.getClaim("roles").asList(Role.class);
        return new JwtBasicClaims()
                .setRoles(roles)
                .setUsername(username)
                .setUserid(userid);
    }
}
