package ru.orobtsovv.gatewayreactiveservice.config;

import ru.orobtsovv.gatewayreactiveservice.filters.JwtAuthenticationFilter;
import ru.orobtsovv.gatewayreactiveservice.filters.MorphHeadersFilter;
import ru.orobtsovv.gatewayreactiveservice.security.JwtWebExchangeMatcher;
import ru.orobtsovv.gatewayreactiveservice.service.JwtService;
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
                .securityContextRepository(NoOpServerSecurityContextRepository.getInstance()) // stateless
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
