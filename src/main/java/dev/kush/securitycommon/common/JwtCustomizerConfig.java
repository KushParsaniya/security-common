package dev.kush.securitycommon.common;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.proc.DefaultJOSEObjectTypeVerifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.core.env.Environment;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;

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
     * Creates a {@link JwtDecoder} configured to validate Auth0-issued access tokens.
     *
     * <p>This method resolves the JWK Set URI from the application's configuration
     * (property: {@code spring.security.oauth2.resourceserver.jwt.jwk-set-uri})
     * using either direct property injection or the Spring {@link Environment} as
     * a fallback. If the URI is missing or blank, an {@link IllegalStateException}
     * is thrown to prevent misconfigured security.</p>
     *
     * <p>The resulting {@link JwtDecoder} is configured to accept tokens with the
     * {@code typ="at+jwt"} header, which Auth0 uses for access tokens. Since this
     * header value is non-standard, the decoder must be explicitly customized
     * to allow it.</p>
     *
     * @param env the Spring environment used to resolve configuration properties
     * @param jwkSetUriFromValue optional injected value of the JWK Set URI
     * @return a fully configured {@code JwtDecoder} for validating Auth0 access tokens
     * @throws IllegalStateException if no JWK Set URI is configured
     */

    @Bean
    @ConditionalOnProperty(name = "identity.provider", havingValue = "auth0", matchIfMissing = true)
    public JwtDecoder jwtDecoder(Environment env,
                                 @Value("${spring.security.oauth2.resourceserver.jwt.jwk-set-uri:}") String jwkSetUriFromValue) {
        String jwkSetUri = jwkSetUriFromValue.isBlank()
                ? env.getProperty("spring.security.oauth2.resourceserver.jwt.jwk-set-uri")
                : jwkSetUriFromValue;

        if (jwkSetUri == null || jwkSetUri.isBlank()) {
            throw new IllegalStateException("Missing property spring.security.oauth2.resourceserver.jwt.jwk-set-uri");
        }

        return NimbusJwtDecoder
                .withJwkSetUri(jwkSetUri)
                .jwtProcessorCustomizer(processor ->
                        processor.setJWSTypeVerifier(new DefaultJOSEObjectTypeVerifier<>(new JOSEObjectType("at+jwt")))
                )
                .build();
    }
}