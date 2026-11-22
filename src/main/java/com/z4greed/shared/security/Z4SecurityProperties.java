package com.z4greed.shared.security;

import java.util.List;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

// Reglas de acceso que cambian por servicio. Ejemplo en application.yml:
//   app:
//     security:
//       public-paths: /auth/**, /actuator/health
//       admin-paths: /ops/**
//       cors-allowed-origins: http://localhost:4200
// Cualquier ruta que no sea pública ni de admin exige un JWT válido.
@ConfigurationProperties(prefix = "app.security")
public record Z4SecurityProperties(
        @DefaultValue("/actuator/health") List<String> publicPaths,
        @DefaultValue List<String> adminPaths,
        @DefaultValue("ADMIN") String adminRole,
        @DefaultValue List<String> corsAllowedOrigins) {
}
