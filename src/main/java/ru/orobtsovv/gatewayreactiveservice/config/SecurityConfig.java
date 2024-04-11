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
                        .pathMatchers("/friends").denyAll()
                        .pathMatchers("/friends/**").hasRole("USER")
                        .pathMatchers("/tags/**").hasRole("USER")
                        .pathMatchers("/profile/**").hasRole("USER")
                        .pathMatchers("/user/**").hasRole("USER")
                        .pathMatchers("/requests/**").hasRole("USER")
                        .pathMatchers("/moderator/**").hasRole("MODERATOR")
                        .pathMatchers("/notifications/tg/ws").hasRole("TG_SERVICE")
                        .pathMatchers("/notifications/**").hasRole("USER")
                        .pathMatchers("/auth/banned/**").hasRole("MODERATOR")
                        .pathMatchers("/auth/signup/tg").hasRole("TG_SERVICE")
                        .pathMatchers("/auth/signin/tg").hasRole("TG_SERVICE")
                        .pathMatchers("/auditorium/**").hasRole("USER")
                        .pathMatchers("/building/**").hasRole("USER")
                        .pathMatchers("/auth/access/grantModerator").denyAll()
                        .pathMatchers("/auth/access/grantTg").denyAll()
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
