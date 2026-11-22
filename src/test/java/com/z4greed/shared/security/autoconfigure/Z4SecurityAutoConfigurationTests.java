package com.z4greed.shared.security.autoconfigure;

import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.options;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.nimbusds.jose.jwk.source.ImmutableSecret;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.List;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringBootConfiguration;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.context.WebApplicationContext;

@SpringBootTest(properties = {
        "app.jwt.secret=" + Z4SecurityAutoConfigurationTests.SECRET,
        "app.security.public-paths=/public/**",
        "app.security.admin-paths=/ops/**",
        "app.security.cors-allowed-origins=http://localhost:4200"
})
class Z4SecurityAutoConfigurationTests {
    static final String SECRET = "test-secret-test-secret-test-secret-32";

    @Autowired private WebApplicationContext context;
    private MockMvc mockMvc;

    @SpringBootConfiguration
    @EnableAutoConfiguration
    static class TestApplication {
        @RestController
        static class TestController {
            @GetMapping({"/public/ping", "/orders/ping", "/ops/ping"})
            String ping() {
                return "pong";
            }
        }
    }

    @BeforeEach
    void setUp() {
        this.mockMvc = MockMvcBuilders.webAppContextSetup(this.context).apply(springSecurity()).build();
    }

    @Test
    void publicPathsDoNotRequireToken() throws Exception {
        this.mockMvc.perform(get("/public/ping")).andExpect(status().isOk());
    }

    @Test
    void otherPathsRequireToken() throws Exception {
        this.mockMvc.perform(get("/orders/ping")).andExpect(status().isUnauthorized());
    }

    @Test
    void anyValidTokenCanCallProtectedPaths() throws Exception {
        this.mockMvc.perform(get("/orders/ping").header("Authorization", bearer("CUSTOMER")))
                .andExpect(status().isOk());
    }

    @Test
    void adminPathsRejectNonAdminRoles() throws Exception {
        this.mockMvc.perform(get("/ops/ping").header("Authorization", bearer("CUSTOMER")))
                .andExpect(status().isForbidden());
    }

    @Test
    void adminPathsAcceptAdminRole() throws Exception {
        this.mockMvc.perform(get("/ops/ping").header("Authorization", bearer("ADMIN")))
                .andExpect(status().isOk());
    }

    @Test
    void tokensSignedWithAnotherSecretAreRejected() throws Exception {
        String foreignToken = token("another-secret-another-secret-another-32", "ADMIN");
        this.mockMvc.perform(get("/orders/ping").header("Authorization", "Bearer " + foreignToken))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void configuredOriginsPassCorsPreflight() throws Exception {
        this.mockMvc.perform(options("/orders/ping")
                        .header("Origin", "http://localhost:4200")
                        .header("Access-Control-Request-Method", "GET"))
                .andExpect(status().isOk())
                .andExpect(header().string("Access-Control-Allow-Origin", "http://localhost:4200"));
    }

    private static String bearer(String role) {
        return "Bearer " + token(SECRET, role);
    }

    private static String token(String secret, String role) {
        SecretKeySpec key = new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256");
        NimbusJwtEncoder encoder = new NimbusJwtEncoder(new ImmutableSecret<>(key));
        JwtClaimsSet claims = JwtClaimsSet.builder()
                .subject("1")
                .issuedAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(300))
                .claim("roles", List.of(role))
                .build();
        JwsHeader header = JwsHeader.with(MacAlgorithm.HS256).build();
        return encoder.encode(JwtEncoderParameters.from(header, claims)).getTokenValue();
    }
}
