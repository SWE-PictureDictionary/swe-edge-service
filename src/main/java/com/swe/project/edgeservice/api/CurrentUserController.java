package com.swe.project.edgeservice.api;

import java.util.List;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class CurrentUserController {

    @GetMapping("/api/me")
    public CurrentUserResponse me(@AuthenticationPrincipal OidcUser user) {
        List<String> roles = user.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .toList();

        String displayName = user.getFullName() != null
                ? user.getFullName()
                : user.getPreferredUsername();

        return new CurrentUserResponse(
                user.getPreferredUsername(),
                displayName,
                roles
        );
    }
}