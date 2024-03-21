package com.example.gatewayreactiveservice.config;

import com.example.gatewayreactiveservice.filters.JwtAuthenticationFilter;
import com.example.gatewayreactiveservice.filters.MorphHeadersFilter;
import com.example.gatewayreactiveservice.security.JwtWebExchangeMatcher;
import com.example.gatewayreactiveservice.service.JwtService;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.context.NoOpServerSecurityContextRepository;

@Configuration
@EnableWebFluxSecurity
@RequiredArgsConstructor
public class SecurityConfig {
    private final JwtService jwtService;
    @Bean
    public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {
        return http
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                .authorizeExchange(authorize -> authorize
                        .pathMatchers("/resource/moderator/**").hasRole("MODERATOR")
                        .pathMatchers("/resource/user/**").hasRole("USER")
                        .pathMatchers("/notifications/ws").hasRole("USER")
                        .anyExchange().permitAll()
                )
                .addFilterAt(jwtFilter(), SecurityWebFiltersOrder.AUTHENTICATION)
                .addFilterAfter(morphHeadersFilter(), SecurityWebFiltersOrder.AUTHORIZATION)
                .securityContextRepository(NoOpServerSecurityContextRepository.getInstance())
                .build();
    }

    private JwtAuthenticationFilter jwtFilter() {
        var matcher = new JwtWebExchangeMatcher();
        return new JwtAuthenticationFilter(matcher, jwtService);
    }

    private MorphHeadersFilter morphHeadersFilter() {
        return new MorphHeadersFilter();
    }
}
