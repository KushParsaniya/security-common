package dev.kush.securitycommon.common;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.proc.DefaultJOSEObjectTypeVerifier;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.security.oauth2.resource.servlet.JwkSetUriJwtDecoderBuilderCustomizer;
import org.springframework.context.annotation.Bean;

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
}