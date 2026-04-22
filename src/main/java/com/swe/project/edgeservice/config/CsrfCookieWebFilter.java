package com.swe.project.edgeservice.config;

import org.springframework.security.web.server.csrf.CsrfToken;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;

import reactor.core.publisher.Mono;

@Component
public class CsrfCookieWebFilter implements WebFilter {

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        exchange.getResponse().beforeCommit(() -> Mono.defer(() -> {
            Mono<CsrfToken> csrfToken = exchange.getAttribute(CsrfToken.class.getName());
            return csrfToken != null ? csrfToken.then() : Mono.empty();
        }));
        return chain.filter(exchange);
    }
}