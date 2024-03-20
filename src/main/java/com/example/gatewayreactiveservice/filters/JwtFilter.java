package com.example.gatewayreactiveservice.filters;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.example.gatewayreactiveservice.client.AuthClient;
import com.example.gatewayreactiveservice.exception.CertsPublicKeyException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import java.util.List;

import static com.example.gatewayreactiveservice.utils.ExceptionConstants.CERTS_UNAVAILABLE;

@Component
@Slf4j
@RequiredArgsConstructor
public class JwtFilter implements WebFilter {
    private final AuthClient authClient;

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
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

        return addPayloadToRequest(mutated, decodedJWT)
                .flatMap(request1 -> {
                    exchange.mutate().request(request1).build();
                    log.info("request headers: " + request1.getHeaders());
                    return chain.filter(exchange);
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
}
