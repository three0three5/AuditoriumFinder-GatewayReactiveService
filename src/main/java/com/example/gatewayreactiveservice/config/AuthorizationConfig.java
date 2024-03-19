package com.example.gatewayreactiveservice.config;

import com.example.gatewayreactiveservice.model.Role;
import lombok.RequiredArgsConstructor;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.List;
import java.util.function.Function;

@Configuration
@RequiredArgsConstructor
public class AuthorizationConfig {
    private final Function<List<Role>, GatewayFilter> filters;

    @Bean
    public GatewayFilter authenticateFilter() {
        return filters.apply(List.of());
    }

    @Bean
    public GatewayFilter userAuthorized() {
        return filters.apply(List.of(Role.ROLE_USER));
    }

    @Bean
    public GatewayFilter moderatorAuthorized() {
        return filters.apply(List.of(Role.ROLE_MODERATOR));
    }
}
