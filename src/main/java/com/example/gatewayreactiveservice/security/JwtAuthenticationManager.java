package com.example.gatewayreactiveservice.security;

import com.example.gatewayreactiveservice.service.JwtService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import reactor.core.publisher.Mono;

@RequiredArgsConstructor
public class JwtAuthenticationManager implements ReactiveAuthenticationManager {
    private final JwtService jwtService;

    @Override
    public Mono<Authentication> authenticate(Authentication authentication) {
        String jwtToken = authentication.getCredentials().toString();

        if (jwtService.isTokenValid(jwtToken)) {
            String username = jwtService.getUsernameFromToken(jwtToken);
            return Mono.just(new UsernamePasswordAuthenticationToken(username, jwtToken, null));
        } else {
            return Mono.error(new AuthenticationException("Invalid JWT token") {
            });
        }
    }
}
