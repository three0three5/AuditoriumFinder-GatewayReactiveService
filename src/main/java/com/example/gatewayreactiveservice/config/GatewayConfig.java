package com.example.gatewayreactiveservice.config;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
@RequiredArgsConstructor
@Slf4j
public class GatewayConfig {
    private final GatewayFilter authenticateFilter;
    private final GatewayFilter userAuthorized;

    @Value("${resourceURI}")
    private final String resourceURI;

    @Value("${authURI}")
    private final String authURI;

    @Value("${notificationsURI}")
    private final String notificationsURI;

    @Bean
    public RouteLocator myRoutes(RouteLocatorBuilder builder) {
        log.info("config");
        return builder.routes()
                .route(p -> p
                        .path("/notifications/ws")
                        .filters(f -> f
                                .filter(authenticateFilter))
                        .uri(notificationsURI))
                .route(p -> p
                        .path("/auth/**")
                        .uri(authURI))
                .route(p -> p
                        .path("/resource/**")
                        .filters(f -> f
                                .filter(userAuthorized))
                        .uri(resourceURI))
                .route(p -> p
                        .path("/notifications/trigger/*")
                        .uri(notificationsURI))
                .build();
    }
}
