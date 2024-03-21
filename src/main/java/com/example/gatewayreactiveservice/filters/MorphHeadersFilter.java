package com.example.gatewayreactiveservice.filters;

import com.example.gatewayreactiveservice.security.BasicPrincipal;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

@Slf4j
public class MorphHeadersFilter implements WebFilter {
    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        return ReactiveSecurityContextHolder.getContext()
                .switchIfEmpty(chain.filter(exchange).then(Mono.empty()))
                .map(SecurityContext::getAuthentication)
                .flatMap(authentication -> {
                    log.info("header morph filter");
                    if (authentication != null && authentication.isAuthenticated()) {
                        log.info("morphing");
                        BasicPrincipal principal = (BasicPrincipal) authentication.getPrincipal();
                        exchange.getRequest().mutate()
                                .header("userid", Integer.toString(principal.getUserid()))
                                .header("username", principal.getUsername())
                                .build();
                    }
                    return chain.filter(exchange);
                });
    }
}
