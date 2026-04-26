package com.swe.project.edgeservice.filter;

import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.data.redis.core.ReactiveStringRedisTemplate;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@Component
public class BadgeHeaderFilter implements GlobalFilter, Ordered {

    private final ReactiveStringRedisTemplate redisTemplate;

    public BadgeHeaderFilter(ReactiveStringRedisTemplate redisTemplate) {
        this.redisTemplate = redisTemplate;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        String learnerId = exchange.getRequest().getHeaders().getFirst("X-Learner-Id");

        if (learnerId == null || learnerId.isBlank()) {
            learnerId = exchange.getRequest().getQueryParams().getFirst("learnerId");
        }

        if (learnerId == null || learnerId.isBlank()) {
            return chain.filter(exchange);
        }

        String finalLearnerId = learnerId;

        return redisTemplate.opsForValue()
                .get("badge:" + finalLearnerId)
                .defaultIfEmpty("0")
                .flatMap(count -> {
                    exchange.getResponse().getHeaders().add("X-Study-Badge-Count", count);
                    return chain.filter(exchange);
                });
    }

    @Override
    public int getOrder() {
        return -1;
    }
}