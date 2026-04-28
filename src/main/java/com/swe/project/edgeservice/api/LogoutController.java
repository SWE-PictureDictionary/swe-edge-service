package com.swe.project.edgeservice.api;

import java.net.URI;
import java.time.Duration;
import java.util.Map;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebSession;
import org.springframework.web.util.UriComponentsBuilder;

import reactor.core.publisher.Mono;

@Controller
public class LogoutController {

    private static final String KEYCLOAK_REGISTRATION_ID = "keycloak";

    private final ReactiveClientRegistrationRepository clientRegistrationRepository;

    public LogoutController(ObjectProvider<ReactiveClientRegistrationRepository> clientRegistrationRepository) {
        this.clientRegistrationRepository = clientRegistrationRepository.getIfAvailable();
    }

    @GetMapping("/logout")
    public Mono<ResponseEntity<Void>> logout(ServerWebExchange exchange, Authentication authentication) {
        Mono<ClientRegistration> clientRegistration = this.clientRegistrationRepository == null
                ? Mono.empty()
                : this.clientRegistrationRepository.findByRegistrationId(KEYCLOAK_REGISTRATION_ID);

        return clientRegistration
                .map(registration -> keycloakLogoutUri(exchange, authentication, registration))
                .defaultIfEmpty(localLoginUri(exchange))
                .flatMap(redirectUri -> invalidateSession(exchange).thenReturn(redirect(redirectUri)));
    }

    private Mono<Void> invalidateSession(ServerWebExchange exchange) {
        expireCookie(exchange, "SESSION");
        expireCookie(exchange, "XSRF-TOKEN");
        return exchange.getSession().flatMap(WebSession::invalidate);
    }

    private void expireCookie(ServerWebExchange exchange, String name) {
        ResponseCookie cookie = ResponseCookie.from(name, "")
                .path("/")
                .maxAge(Duration.ZERO)
                .build();
        exchange.getResponse().addCookie(cookie);
    }

    private ResponseEntity<Void> redirect(URI location) {
        return ResponseEntity.status(HttpStatus.FOUND)
                .location(location)
                .build();
    }

    private URI keycloakLogoutUri(
            ServerWebExchange exchange,
            Authentication authentication,
            ClientRegistration clientRegistration
    ) {
        URI endSessionEndpoint = endSessionEndpoint(clientRegistration);
        if (endSessionEndpoint == null) {
            return localLoginUri(exchange);
        }

        UriComponentsBuilder builder = UriComponentsBuilder.fromUri(endSessionEndpoint)
                .queryParam("client_id", clientRegistration.getClientId())
                .queryParam("post_logout_redirect_uri", localLoginUri(exchange));

        String idToken = idToken(authentication);
        if (idToken != null && !idToken.isBlank()) {
            builder.queryParam("id_token_hint", idToken);
        }

        return builder.build().encode().toUri();
    }

    private URI endSessionEndpoint(ClientRegistration clientRegistration) {
        Map<String, Object> metadata = clientRegistration.getProviderDetails().getConfigurationMetadata();
        Object endSessionEndpoint = metadata.get("end_session_endpoint");
        if (endSessionEndpoint != null) {
            return URI.create(endSessionEndpoint.toString());
        }

        Object issuer = metadata.get("issuer");
        if (issuer == null) {
            return null;
        }

        return URI.create(issuer + "/protocol/openid-connect/logout");
    }

    private String idToken(Authentication authentication) {
        if (authentication != null && authentication.getPrincipal() instanceof OidcUser oidcUser) {
            return oidcUser.getIdToken().getTokenValue();
        }

        return null;
    }

    private URI localLoginUri(ServerWebExchange exchange) {
        HttpHeaders headers = exchange.getRequest().getHeaders();
        String scheme = firstHeader(headers, "X-Forwarded-Proto", exchange.getRequest().getURI().getScheme());
        String host = firstHeader(headers, "X-Forwarded-Host", headers.getFirst(HttpHeaders.HOST));

        if (host == null || host.isBlank()) {
            host = exchange.getRequest().getURI().getAuthority();
        }

        return URI.create(scheme + "://" + host + "/login.html");
    }

    private String firstHeader(HttpHeaders headers, String name, String fallback) {
        String value = headers.getFirst(name);
        return value == null || value.isBlank() ? fallback : value;
    }
}
