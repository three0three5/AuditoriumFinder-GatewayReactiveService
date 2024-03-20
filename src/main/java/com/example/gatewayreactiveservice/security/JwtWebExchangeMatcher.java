package com.example.gatewayreactiveservice.security;

import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcher;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Component
public class JwtWebExchangeMatcher implements ServerWebExchangeMatcher {
    @Override
    public Mono<MatchResult> matches(ServerWebExchange exchange) {
        List<String> headers = exchange.getRequest().getHeaders().get("Authorization");
        if (headers == null || headers.isEmpty()
                || !headers.get(0).startsWith("Bearer ")) return MatchResult.notMatch();
        Map<String, Object> token = new HashMap<>();
        token.put("token", headers.get(0).substring(7));
        return MatchResult.match(token);
    }
}
