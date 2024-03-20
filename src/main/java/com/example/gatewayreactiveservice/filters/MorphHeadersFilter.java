package com.example.gatewayreactiveservice.filters;

import com.example.gatewayreactiveservice.security.BasicPrincipal;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

public class MorphHeadersFilter implements WebFilter {
    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        return ReactiveSecurityContextHolder.getContext()
                .map(SecurityContext::getAuthentication)
                .flatMap(authentication -> {
                    var mutated = exchange.getRequest();
                    if (authentication != null) {
                        BasicPrincipal principal = (BasicPrincipal) authentication.getPrincipal();
                        mutated.mutate()
                                .header("userid", Integer.toString(principal.getUserid()))
                                .header("username", principal.getUsername())
                                .build();
                        exchange.mutate().request(mutated).build();
                    }
                    return chain.filter(exchange);
                });
    }
}
