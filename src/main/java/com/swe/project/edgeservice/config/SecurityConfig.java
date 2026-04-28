package com.swe.project.edgeservice.config;

import java.io.IOException;
import java.util.Base64;
import java.util.Collection;
import java.util.HashSet;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcReactiveOAuth2UserService;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.userinfo.ReactiveOAuth2UserService;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.authentication.HttpStatusServerEntryPoint;
import org.springframework.security.web.server.csrf.CookieServerCsrfTokenRepository;
import org.springframework.security.web.server.csrf.CsrfWebFilter;
import org.springframework.security.web.server.csrf.ServerCsrfTokenRequestAttributeHandler;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcher.MatchResult;
import org.springframework.web.server.ServerWebExchange;

import reactor.core.publisher.Mono;

@Profile("!test")
@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    @Bean
    SecurityWebFilterChain springSecurityFilterChain(
            ServerHttpSecurity http
    ) {
        return http
                .csrf(csrf -> csrf
                        .csrfTokenRepository(CookieServerCsrfTokenRepository.withHttpOnlyFalse())
                        .csrfTokenRequestHandler(new ServerCsrfTokenRequestAttributeHandler())
                        .requireCsrfProtectionMatcher(SecurityConfig::requiresCsrfProtection))
                .exceptionHandling(ex -> ex
                        .authenticationEntryPoint(
                                new HttpStatusServerEntryPoint(HttpStatus.UNAUTHORIZED)))
                .authorizeExchange(exchanges -> exchanges
                        .pathMatchers("/", "/homepage.html", "/login.html", "/index.html").permitAll()
                        .pathMatchers("/logout").permitAll()
                        .pathMatchers("/oauth2/**", "/login/**").permitAll()
                        .pathMatchers("/api/me").authenticated()

                        .pathMatchers(HttpMethod.GET, "/topics", "/topics/**").authenticated()
                        .pathMatchers(HttpMethod.POST, "/topics").hasRole("CONTENT_MANAGER")
                        .pathMatchers(HttpMethod.POST, "/topics/*/hotspots", "/topics/*/images", "/topics/*/audio")
                                .hasAnyRole("CONTENT_MANAGER", "HOTSPOT_EDITOR")
                        .pathMatchers(HttpMethod.PUT, "/topics/*/hotspots/*")
                                .hasAnyRole("CONTENT_MANAGER", "HOTSPOT_EDITOR")
                        .pathMatchers(HttpMethod.DELETE, "/topics/*/hotspots/*")
                                .hasAnyRole("CONTENT_MANAGER", "HOTSPOT_EDITOR")
                        .pathMatchers(HttpMethod.DELETE, "/topics/*").hasRole("CONTENT_MANAGER")

                        .pathMatchers(HttpMethod.POST, "/progress/**")
                                .hasAnyRole("CONTENT_MANAGER", "HOTSPOT_EDITOR", "LEARNER")
                        .pathMatchers(HttpMethod.DELETE, "/progress/**")
                                .hasAnyRole("CONTENT_MANAGER", "HOTSPOT_EDITOR", "LEARNER")
                        .pathMatchers(HttpMethod.GET, "/progress/**").authenticated()

                        .anyExchange().authenticated()
                )
                .oauth2Login(Customizer.withDefaults())
                .logout(logout -> logout.disable())
                .build();
    }

    private static Mono<MatchResult> requiresCsrfProtection(ServerWebExchange exchange) {
        String path = exchange.getRequest().getPath().pathWithinApplication().value();
        if ("/logout".equals(path)) {
            return MatchResult.notMatch();
        }

        return CsrfWebFilter.DEFAULT_CSRF_MATCHER.matches(exchange);
    }

    @Bean
    ReactiveOAuth2UserService<OidcUserRequest, OidcUser> oidcUserService() {
        OidcReactiveOAuth2UserService delegate = new OidcReactiveOAuth2UserService();

        return userRequest -> delegate.loadUser(userRequest).map(oidcUser -> {
            Set<GrantedAuthority> mappedAuthorities = new HashSet<>(oidcUser.getAuthorities());

            addRolesFromClaims(oidcUser.getClaims(), mappedAuthorities);
            addRolesFromAccessToken(userRequest.getAccessToken().getTokenValue(), mappedAuthorities);

            return new DefaultOidcUser(
                    mappedAuthorities,
                    oidcUser.getIdToken(),
                    oidcUser.getUserInfo(),
                    "preferred_username"
            );
        });
    }

    private static void addRolesFromAccessToken(
            String accessToken,
            Set<GrantedAuthority> mappedAuthorities
    ) {
        if (accessToken == null || accessToken.isBlank()) {
            return;
        }

        String[] tokenParts = accessToken.split("\\.");
        if (tokenParts.length < 2) {
            return;
        }

        try {
            byte[] payload = Base64.getUrlDecoder().decode(tokenParts[1]);
            Map<String, Object> claims = OBJECT_MAPPER.readValue(
                    payload,
                    new TypeReference<>() {}
            );
            addRolesFromClaims(claims, mappedAuthorities);
        } catch (IllegalArgumentException | IOException ignored) {
            // Keep the authenticated user if a non-JWT access token is ever used.
        }
    }

    private static void addRolesFromClaims(
            Map<String, Object> claims,
            Set<GrantedAuthority> mappedAuthorities
    ) {
        Object realmAccessObj = claims.get("realm_access");
        if (realmAccessObj instanceof Map<?, ?> realmAccess) {
            addRoles(realmAccess.get("roles"), mappedAuthorities);
        }

        Object resourceAccessObj = claims.get("resource_access");
        if (resourceAccessObj instanceof Map<?, ?> resourceAccess) {
            resourceAccess.values().forEach(resourceObj -> {
                if (resourceObj instanceof Map<?, ?> resource) {
                    addRoles(resource.get("roles"), mappedAuthorities);
                }
            });
        }
    }

    private static void addRoles(
            Object rolesObj,
            Set<GrantedAuthority> mappedAuthorities
    ) {
        if (rolesObj instanceof Collection<?> roles) {
            roles.stream()
                    .map(Object::toString)
                    .filter(role -> !role.isBlank())
                    .map(SecurityConfig::roleAuthority)
                    .map(SimpleGrantedAuthority::new)
                    .forEach(mappedAuthorities::add);
        }
    }

    private static String roleAuthority(String role) {
        if (role.startsWith("ROLE_")) {
            return role;
        }

        return "ROLE_" + role.toUpperCase(Locale.ROOT).replace('-', '_');
    }
}
