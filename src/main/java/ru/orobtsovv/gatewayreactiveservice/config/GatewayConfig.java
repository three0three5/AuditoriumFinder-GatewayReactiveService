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
    @Value("${services.auth}")
    private final String authServiceUrl;

    @Value("${services.user}")
    private final String userServiceUrl;

    @Value("${services.aud}")
    private final String auditoriumServiceUrl;

    @Value("${services.notifier}")
    private final String notificationServiceUrl;

    @Bean
    public RouteLocator myRoutes(RouteLocatorBuilder builder) {
        log.info("config");
        return builder.routes()
                .route(p -> p
                        .path("/notifications/**")
                        .uri(notificationServiceUrl))
                .route(p -> p
                        .path("/auth/**")
                        .uri(authServiceUrl))
                .route(p -> p
                        .path("/moderator/**")
                        .uri(userServiceUrl))
                .route(p -> p
                        .path("/requests/**")
                        .uri(userServiceUrl))
                .route(p -> p
                        .path("/user/**")
                        .uri(userServiceUrl))
                .route(p -> p
                        .path("/profile/**")
                        .uri(userServiceUrl))
                .route(p -> p
                        .path("/tags/**")
                        .uri(userServiceUrl))
                .route(p -> p
                        .path("/friends/**")
                        .uri(userServiceUrl))
                .build();
    }
}
