package com.swe.project.edgeservice.controller;

import org.springframework.data.redis.core.ReactiveStringRedisTemplate;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Mono;

import java.util.Map;

@RestController
@RequestMapping("/notifications")
public class BadgeController {

    private final ReactiveStringRedisTemplate redisTemplate;

    public BadgeController(ReactiveStringRedisTemplate redisTemplate) {
        this.redisTemplate = redisTemplate;
    }

    @GetMapping("/badge/{learnerId}")
    public Mono<Map<String, Object>> getBadge(@PathVariable String learnerId) {
        return redisTemplate.opsForValue()
                .get("badge:" + learnerId)
                .defaultIfEmpty("0")
                .map(value -> Map.of(
                        "learnerId", learnerId,
                        "badgeCount", Long.parseLong(value)
                ));
    }

    @DeleteMapping("/badge/{learnerId}")
    public Mono<Map<String, Object>> clearBadge(@PathVariable String learnerId) {
        return redisTemplate.delete("badge:" + learnerId)
                .thenReturn(Map.of(
                        "learnerId", learnerId,
                        "badgeCount", 0
                ));
    }
}