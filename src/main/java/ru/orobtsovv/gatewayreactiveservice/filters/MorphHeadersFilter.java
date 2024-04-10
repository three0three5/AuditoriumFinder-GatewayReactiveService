package ru.orobtsovv.gatewayreactiveservice.filters;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;
import ru.orobtsovv.gatewayreactiveservice.security.BasicPrincipal;

import static ru.orobtsovv.gatewayreactiveservice.utils.ExceptionConstants.USERID_HEADER;

@Slf4j
public class MorphHeadersFilter implements WebFilter {
    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        return ReactiveSecurityContextHolder.getContext()
                .switchIfEmpty(chain.filter(exchange).then(Mono.empty()))
                .map(SecurityContext::getAuthentication)
                .flatMap(authentication -> {
                    log.info("header morph filter");
                    removeHeaders(exchange);
                    if (authentication != null && authentication.isAuthenticated()) {
                        log.info("morphing");
                        BasicPrincipal principal = (BasicPrincipal) authentication.getPrincipal();
                        exchange.getRequest().mutate()
                                .header(USERID_HEADER, Integer.toString(principal.getUserid()))
                                .build();
                    }
                    return chain.filter(exchange);
                });
    }

    private void removeHeaders(ServerWebExchange exchange) {
        exchange.getRequest().mutate()
                .headers(h -> h.remove(USERID_HEADER))
                .build();
    }
}
