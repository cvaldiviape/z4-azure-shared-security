package com.z4greed.shared.security.autoconfigure;

import com.z4greed.shared.security.JwtRolesConverter;
import com.z4greed.shared.security.Z4JwtProperties;
import com.z4greed.shared.security.Z4SecurityProperties;
import java.nio.charset.StandardCharsets;
import java.util.List;
import javax.crypto.spec.SecretKeySpec;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

// Configura cada servicio como "resource server": valida el JWT que emite auth-service en cada petición.
// Se carga antes que la seguridad por defecto de Spring Boot para que esta no cree su propio usuario ni filtro.
// Cualquier bean que el servicio defina con el mismo tipo reemplaza al de la librería (@ConditionalOnMissingBean).
@AutoConfiguration(beforeName = {
        "org.springframework.boot.security.autoconfigure.UserDetailsServiceAutoConfiguration",
        "org.springframework.boot.security.autoconfigure.web.servlet.ServletWebSecurityAutoConfiguration",
        "org.springframework.boot.security.autoconfigure.actuate.web.servlet.ManagementWebSecurityAutoConfiguration",
        "org.springframework.boot.security.oauth2.server.resource.autoconfigure.OAuth2ResourceServerAutoConfiguration",
        "org.springframework.boot.security.oauth2.server.resource.autoconfigure.web.OAuth2ResourceServerWebSecurityAutoConfiguration"
})
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
@EnableWebSecurity
@EnableConfigurationProperties({Z4JwtProperties.class, Z4SecurityProperties.class})
public class Z4SecurityAutoConfiguration {
    private static final String HMAC_SHA256 = "HmacSHA256";

    @Bean
    @ConditionalOnMissingBean
    public JwtDecoder jwtDecoder(Z4JwtProperties jwtProperties) {
        SecretKeySpec secretKey = new SecretKeySpec(jwtProperties.secret().getBytes(StandardCharsets.UTF_8), HMAC_SHA256);
        return NimbusJwtDecoder.withSecretKey(secretKey)
                .macAlgorithm(MacAlgorithm.HS256)
                .build();
    }

    // Orden de las reglas: primero lo público, luego lo de admin y al final "cualquier otra ruta exige JWT".
    @Bean
    @ConditionalOnMissingBean(SecurityFilterChain.class)
    public SecurityFilterChain z4SecurityFilterChain(HttpSecurity http, Z4SecurityProperties securityProperties) throws Exception {
        String[] publicPaths = securityProperties.publicPaths().toArray(String[]::new);
        String[] adminPaths = securityProperties.adminPaths().toArray(String[]::new);

        return http.csrf(AbstractHttpConfigurer::disable)
                .cors(cors -> cors.configurationSource(corsConfigurationSource(securityProperties.corsAllowedOrigins())))
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(authorize -> {
                    authorize.requestMatchers(publicPaths).permitAll();
                    if (adminPaths.length > 0) {
                        authorize.requestMatchers(adminPaths).hasRole(securityProperties.adminRole());
                    }
                    authorize.anyRequest().authenticated();
                })
                .oauth2ResourceServer(oauth2 -> oauth2.jwt(jwt -> jwt.jwtAuthenticationConverter(new JwtRolesConverter())))
                .build();
    }

    // No se registra como bean: Spring MVC ya expone otro CorsConfigurationSource (HandlerMappingIntrospector)
    // y Spring Security podría tomar ese en lugar de este.
    // Sin orígenes configurados, el navegador no puede llamar al servicio desde otro dominio (por defecto, cerrado).
    private static CorsConfigurationSource corsConfigurationSource(List<String> allowedOrigins) {
        CorsConfiguration corsConfiguration = new CorsConfiguration();
        corsConfiguration.setAllowedOrigins(allowedOrigins);
        corsConfiguration.setAllowedMethods(List.of("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"));
        corsConfiguration.setAllowedHeaders(List.of("Authorization", "Content-Type"));

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", corsConfiguration);
        return source;
    }
}
