package ru.orobtsovv.gatewayreactiveservice.config;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
@RequiredArgsConstructor
@Slf4j
public class GatewayConfig {
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
                        .uri(notificationsURI))
                .route(p -> p
                        .path("/auth/**")
                        .uri(authURI))
                .route(p -> p
                        .path("/resource/**")
                        .uri(resourceURI))
                .route(p -> p
                        .path("/notifications/trigger/*")
                        .uri(notificationsURI))
                .build();
    }
}
