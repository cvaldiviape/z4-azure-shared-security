package com.z4greed.shared.security;

import org.springframework.boot.context.properties.ConfigurationProperties;

// app.jwt.secret: la misma clave con la que auth-service firma los tokens (HS256, mínimo 32 bytes).
@ConfigurationProperties(prefix = "app.jwt")
public record Z4JwtProperties(String secret) {}
