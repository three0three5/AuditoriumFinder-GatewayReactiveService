package com.example.gatewayreactiveservice.config;

import com.example.gatewayreactiveservice.filters.JwtAuthenticationFilter;
import com.example.gatewayreactiveservice.filters.JwtFilter;
import com.example.gatewayreactiveservice.security.JwtAuthenticationManager;
import com.example.gatewayreactiveservice.security.JwtWebExchangeMatcher;
import com.example.gatewayreactiveservice.service.JwtService;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;

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
                        .pathMatchers("/auth/**").permitAll()
                        .pathMatchers("/resource/moderator/*").authenticated()
                        .pathMatchers("/resource/user/*").authenticated()
                )
                .addFilterBefore(jwtFilter(), SecurityWebFiltersOrder.AUTHORIZATION)
                .build();
    }

    @Bean
    public ReactiveAuthenticationManager reactiveAuthenticationManager() {
        return new JwtAuthenticationManager(jwtService);
    }

    @Bean
    public JwtAuthenticationFilter jwtFilter() {
        var matcher = new JwtWebExchangeMatcher();
        return new JwtAuthenticationFilter(reactiveAuthenticationManager(), matcher);
    }


}
