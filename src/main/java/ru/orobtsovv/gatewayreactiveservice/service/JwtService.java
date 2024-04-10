package ru.orobtsovv.gatewayreactiveservice.service;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import ru.orobtsovv.gatewayreactiveservice.client.AuthClient;
import ru.orobtsovv.gatewayreactiveservice.model.JwtBasicClaims;
import ru.orobtsovv.gatewayreactiveservice.exception.CertsPublicKeyException;
import ru.orobtsovv.gatewayreactiveservice.model.Role;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.util.List;

import static ru.orobtsovv.gatewayreactiveservice.utils.ExceptionConstants.CERTS_UNAVAILABLE;
import static ru.orobtsovv.gatewayreactiveservice.utils.ExceptionConstants.ISSUER;

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
                            .withIssuer(ISSUER)
                            .build();
                    return verifier.verify(token);
                });
    }

    public JwtBasicClaims getBasicClaims(DecodedJWT jwt) {
        int userid = jwt.getClaim("userid").asInt();
        List<Role> roles = jwt.getClaim("roles").asList(Role.class);
        return new JwtBasicClaims()
                .setRoles(roles)
                .setUserid(userid);
    }
}
