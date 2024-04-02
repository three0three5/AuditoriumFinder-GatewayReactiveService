package ru.orobtsovv.gatewayreactiveservice.filters;

import com.auth0.jwt.exceptions.JWTVerificationException;
import ru.orobtsovv.gatewayreactiveservice.exception.CertsPublicKeyException;
import ru.orobtsovv.gatewayreactiveservice.model.JwtBasicClaims;
import ru.orobtsovv.gatewayreactiveservice.service.JwtService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcher;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

@RequiredArgsConstructor
@Slf4j
public class JwtAuthenticationFilter implements WebFilter {
    private final ServerWebExchangeMatcher matcher;
    private final JwtService jwtService;

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        return this.matcher.matches(exchange)
                .filter(matchResult -> {
                    log.info("checking matching: " + matchResult.isMatch());
                    return matchResult.isMatch();
                })
                .map((matchResult) -> {
                    log.info("mapping matchResult");
                    return matchResult.getVariables().get("token");
                })
                .switchIfEmpty(chain.filter(exchange).then(Mono.empty()))
                .flatMap((token) -> authenticate((String) token))
                .flatMap(authentication ->
                        chain.filter(exchange)
                                .contextWrite(ReactiveSecurityContextHolder.withAuthentication(authentication)))
                .onErrorResume(JWTVerificationException.class, ex -> {
                    log.info("JWTVerificationException");
                    exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
                    return exchange.getResponse().setComplete();
                })
                .onErrorResume(CertsPublicKeyException.class, ex -> {
                    exchange.getResponse().setStatusCode(HttpStatus.SERVICE_UNAVAILABLE);
                    return exchange.getResponse().setComplete();
                });
    }

    private Mono<Authentication> authenticate(String token) {
        return this.jwtService.verify(token)
                .map(decodedJWT -> {
                    JwtBasicClaims claims = jwtService.getBasicClaims(decodedJWT);
                    return basicClaimsToAuthentication(claims);
                });
    }

    private Authentication basicClaimsToAuthentication(JwtBasicClaims claims) {
        return new UsernamePasswordAuthenticationToken(
                claims, null, claims.getRoles());
    }
}
