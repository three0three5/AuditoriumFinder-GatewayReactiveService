package com.example.gatewayreactiveservice.filters;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.example.gatewayreactiveservice.client.AuthClient;
import com.example.gatewayreactiveservice.exception.CertsPublicKeyException;
import com.example.gatewayreactiveservice.model.Role;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.Set;
import java.util.function.Function;
import java.util.stream.Collectors;

import static com.example.gatewayreactiveservice.utils.ExceptionConstants.CERTS_UNAVAILABLE;

@Component
@Slf4j
@RequiredArgsConstructor
public class AuthFilter implements Function<List<Role>, GatewayFilter> {
    private final AuthClient authClient;

    @Override
    public GatewayFilter apply(List<Role> requiredRoles) {
        return (exchange, chain) -> {
            ServerHttpRequest request = exchange.getRequest();
            var authHeaders = getAuthHeader(request);
            if (authHeaders.isEmpty() || !authHeaders.get(0).startsWith("Bearer ")) {
                exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
                return exchange.getResponse().setComplete();
            }

            String token = authHeaders.get(0).substring(7);
            var mutated =
                    request.mutate().headers(httpHeaders -> httpHeaders.remove("Authorization")).build();
            log.info(token);

            Mono<DecodedJWT> decodedJWT = verify(token);

            Mono<Boolean> isAuthorized = authorized(decodedJWT, requiredRoles);

            return isAuthorized
                    .flatMap(auth -> {
                        if (!auth) {
                            exchange.getResponse().setStatusCode(HttpStatus.FORBIDDEN);
                            return exchange.getResponse().setComplete();
                        }
                        return addPayloadToRequest(mutated, decodedJWT)
                                .flatMap(request1 -> {
                                    exchange.mutate().request(request1).build();
                                    log.info("request headers: " + request1.getHeaders());
                                    return chain.filter(exchange);
                                });
                    }).onErrorResume(throwable -> {
                        if (throwable instanceof JWTVerificationException) {
                            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
                            return exchange.getResponse().setComplete();
                        } else if (throwable instanceof CertsPublicKeyException) {
                            exchange.getResponse().setStatusCode(HttpStatus.SERVICE_UNAVAILABLE);
                            return exchange.getResponse().setComplete();
                        }
                        log.error(throwable.getMessage());
                        throw new RuntimeException(throwable);
                    });
        };
    }

    private Mono<Boolean> authorized(Mono<DecodedJWT> decodedJWT, List<Role> requiredRoles) {
        if (requiredRoles == null || requiredRoles.isEmpty()) return Mono.just(true);
        return decodedJWT.map(jwt -> {
            List<String> stringRoles = jwt.getClaim("roles").asList(String.class);
            Set<Role> givenRoles = stringRoles.stream()
                    .map(stringRole -> {
                        try {
                            return Role.valueOf(stringRole);
                        } catch (IllegalArgumentException e) {
                            return null;
                        }
                    }).collect(Collectors.toSet());
            for (Role required : requiredRoles) {
                if (!givenRoles.contains(required)) return false;
            }
            return true;
        });
    }

    private Mono<ServerHttpRequest> addPayloadToRequest(ServerHttpRequest request, Mono<DecodedJWT> jwt) {
        return jwt
                .doOnNext(decodedJWT -> log.info(decodedJWT.getClaim("userid").asInt().toString()))
                .map(decoded -> request.mutate()
                        .header("userid", decoded.getClaim("userid").asInt().toString())
                        .header("roles", decoded.getClaim("roles").asArray(String.class))
                        .header("username", decoded.getClaim("username").asString())
                        .build()
                );
    }

    private List<String> getAuthHeader(ServerHttpRequest request) {
        return request.getHeaders().getOrEmpty("Authorization");
    }

    private Mono<DecodedJWT> verify(String token) {
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
}
