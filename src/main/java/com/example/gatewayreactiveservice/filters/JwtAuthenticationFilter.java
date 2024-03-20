package com.example.gatewayreactiveservice.filters;

import com.auth0.jwt.exceptions.JWTVerificationException;
import com.example.gatewayreactiveservice.exception.CertsPublicKeyException;
import lombok.RequiredArgsConstructor;
import org.springframework.core.log.LogMessage;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.server.WebFilterExchange;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcher;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

@RequiredArgsConstructor
public class JwtAuthenticationFilter implements WebFilter {
    private final ServerWebExchangeMatcher matcher;
    private final ReactiveAuthenticationManager authenticationManager;

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        return this.matcher.matches(exchange)
                .filter(ServerWebExchangeMatcher.MatchResult::isMatch)
                .map((matchResult) -> matchResult.getVariables().get("token"))
                .switchIfEmpty(chain.filter(exchange).then(Mono.empty()))
                .flatMap((token) -> authenticate(token))
                .onErrorResume(JWTVerificationException.class, ex -> {
                    exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
                    return exchange.getResponse().setComplete();
                })
                .onErrorResume(CertsPublicKeyException.class, ex -> {
                    exchange.getResponse().setStatusCode(HttpStatus.SERVICE_UNAVAILABLE);
                    return exchange.getResponse().setComplete();
                });
//                    if (throwable instanceof JWTVerificationException) {
//                        exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
//                        return exchange.getResponse().setComplete();
//                    } else if (throwable instanceof CertsPublicKeyException) {
//                        exchange.getResponse().setStatusCode(HttpStatus.SERVICE_UNAVAILABLE);
//                        return exchange.getResponse().setComplete();
//                    }
//                    log.error(throwable.getMessage());
//                    throw new RuntimeException(throwable);
//                });
    }

    private Mono<Void> authenticate(Authentication token) {
        Mono<Authentication> result = this.authenticationManager.authenticate(token);
    }
}
