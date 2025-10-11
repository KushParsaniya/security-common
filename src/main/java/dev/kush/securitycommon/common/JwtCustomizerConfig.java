package dev.kush.securitycommon.common;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.proc.DefaultJOSEObjectTypeVerifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.security.oauth2.resource.servlet.JwkSetUriJwtDecoderBuilderCustomizer;
import org.springframework.context.annotation.Bean;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Auto-configuration class for customizing JWT decoder behavior.
 * 
 * <p>This configuration class provides customizations for JWT token processing,
 * specifically for Auth0 integration. It configures the JWT decoder to properly
 * handle Auth0's access token format which uses the "at+jwt" type header.</p>
 * 
 * <p>The customization ensures that Auth0 access tokens are properly validated
 * by setting up the appropriate JOSE object type verifier.</p>
 * 
 * @author Kush Parsaniya
 * @since 0.0.1
 */
@AutoConfiguration
public class JwtCustomizerConfig {

    /**
     * Provide a comma separated list of allowed origins:
     * FRONTEND_ORIGINS=http://localhost:5174,http://host.docker.internal:5174
     * or use "*" for permissive dev mode (no credentials).
     */
    @Value("${frontend.origins}")
    private String frontendOrigins;

    /**
     * Parses the frontend origins from a comma-separated string.
     *
     * @return a list of trimmed, non-empty origin strings
     */
    private List<String> parseOrigins() {
        return Arrays.stream(frontendOrigins.split(","))
                .map(String::trim)
                .filter(s -> !s.isEmpty())
                .collect(Collectors.toList());
    }

    /**
     * Creates a JWT decoder builder customizer for Auth0 integration.
     * 
     * <p>This customizer configures the JWT processor to accept tokens with the
     * "at+jwt" type header, which is used by Auth0 for access tokens. This is
     * necessary because Auth0 access tokens have a specific JWT type that needs
     * to be explicitly validated.</p>
     * 
     * <p>The customizer is only active when the identity provider is configured
     * as "auth0" or when no identity provider is explicitly configured (default).</p>
     * 
     * @return a JWT decoder builder customizer that sets up Auth0-compatible token validation
     */
    @Bean
    @ConditionalOnProperty(name = "identity.provider", havingValue = "auth0", matchIfMissing = true)
    public JwkSetUriJwtDecoderBuilderCustomizer customizer() {
        return builder -> builder.jwtProcessorCustomizer(processor ->
            processor.setJWSTypeVerifier(new DefaultJOSEObjectTypeVerifier<>(new JOSEObjectType("at+jwt")))
        );
    }

    /**
     * Creates a JWT authentication converter that extracts roles from JWT tokens.
     *
     * <p>This converter is configured to extract user roles from the appropriate
     * claim based on the configured identity provider (Keycloak or Auth0). It sets
     * the authority prefix to "ROLE_" to align with Spring Security's role
     * conventions.</p>
     *
     * <p>The converter is only created if no other JwtAuthenticationConverter bean
     * is already defined in the application context.</p>
     *
     * @param identityProvider the configured identity provider (e.g., "keycloak" or "auth0")
     * @return a JwtAuthenticationConverter that extracts roles from the JWT token
     */
    @Bean
    @ConditionalOnMissingBean(JwtAuthenticationConverter.class)
    JwtAuthenticationConverter jwtAuthenticationConverter(@Value("${identity.provider}") String identityProvider) {
        JwtAuthenticationConverter jwtAuthenticationConverter = new JwtAuthenticationConverter();

        JwtGrantedAuthoritiesConverter jwtGrantedAuthoritiesConverter = new JwtGrantedAuthoritiesConverter();
        if ("keycloak".equalsIgnoreCase(identityProvider)) {
            jwtGrantedAuthoritiesConverter.setAuthoritiesClaimName(AuthConstants.KEYCLOAK_ROLE_CLAIM);
        } else {
            jwtGrantedAuthoritiesConverter.setAuthoritiesClaimName(AuthConstants.AUTH0_ROLE_CLAIM);
        }
        jwtGrantedAuthoritiesConverter.setAuthorityPrefix("ROLE_");
        jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(jwtGrantedAuthoritiesConverter);
        return jwtAuthenticationConverter;
    }

    /**
     * Creates a CORS configuration source based on allowed frontend origins.
     *
     * <p>This configuration allows cross-origin requests from the specified
     * frontend origins. It supports both specific origins and a permissive
     * mode using "*". In permissive mode, credentials are not allowed.</p>
     *
     * <p>The CORS configuration is only created if no other CorsConfigurationSource
     * bean is already defined in the application context.</p>
     *
     * @return a CorsConfigurationSource that defines CORS settings for the application
     */
    @Bean
    @ConditionalOnMissingBean(CorsConfigurationSource.class)
    CorsConfigurationSource corsConfigurationSource() {
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        CorsConfiguration corsConfiguration = new CorsConfiguration();

        List<String> origins = parseOrigins();

        if (origins.size() == 1 && "*".equals(origins.get(0))) {
            // permissive dev mode: allow any origin pattern, but MUST NOT allow credentials
            corsConfiguration.setAllowedOriginPatterns(List.of("*"));
            corsConfiguration.setAllowCredentials(false);
        } else {
            corsConfiguration.setAllowedOrigins(origins);
            corsConfiguration.setAllowCredentials(true); // allow cookies / credentials if needed
        }

        corsConfiguration.addAllowedHeader("*");
        corsConfiguration.addAllowedMethod("*");
        corsConfiguration.setMaxAge(3600L);

        source.registerCorsConfiguration("/**", corsConfiguration);
        return source;
    }
}