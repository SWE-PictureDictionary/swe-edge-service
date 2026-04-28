package com.swe.project.edgeservice.config;

import java.util.Collection;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

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

            Object realmAccessObj = oidcUser.getClaims().get("realm_access");
            if (realmAccessObj instanceof Map<?, ?> realmAccess) {
                Object rolesObj = realmAccess.get("roles");
                if (rolesObj instanceof Collection<?> roles) {
                    roles.stream()
                            .map(Object::toString)
                            .map(role -> "ROLE_" + role.toUpperCase().replace('-', '_'))
                            .map(SimpleGrantedAuthority::new)
                            .forEach(mappedAuthorities::add);
                }
            }

            return new DefaultOidcUser(
                    mappedAuthorities,
                    oidcUser.getIdToken(),
                    oidcUser.getUserInfo(),
                    "preferred_username"
            );
        });
    }
}
