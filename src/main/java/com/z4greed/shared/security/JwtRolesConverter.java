package com.z4greed.shared.security;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;

// auth-service emite los roles en el claim "roles" (ej. ["ADMIN"]).
// Spring Security los espera como autoridades con prefijo: ROLE_ADMIN. Este converter hace esa traducción.
public class JwtRolesConverter implements Converter<Jwt, AbstractAuthenticationToken> {
    private static final String ROLES_CLAIM = "roles";
    private static final String ROLE_PREFIX = "ROLE_";

    private final JwtAuthenticationConverter delegate;

    public JwtRolesConverter() {
        JwtGrantedAuthoritiesConverter authoritiesConverter = new JwtGrantedAuthoritiesConverter();
        authoritiesConverter.setAuthoritiesClaimName(ROLES_CLAIM);
        authoritiesConverter.setAuthorityPrefix(ROLE_PREFIX);

        this.delegate = new JwtAuthenticationConverter();
        this.delegate.setJwtGrantedAuthoritiesConverter(authoritiesConverter);
    }

    @Override
    public AbstractAuthenticationToken convert(Jwt jwt) {
        return this.delegate.convert(jwt);
    }
}
