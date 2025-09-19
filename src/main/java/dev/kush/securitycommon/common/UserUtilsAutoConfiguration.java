package dev.kush.securitycommon.common;

import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;

/**
 * Auto-configuration class for UserUtils bean registration.
 * 
 * <p>This configuration class automatically registers the appropriate UserUtils
 * implementation based on the configured identity provider. It supports both
 * Auth0 and Keycloak identity providers through conditional bean registration.</p>
 * 
 * <p>The configuration uses the "identity.provider" property to determine which
 * implementation to register:
 * <ul>
 * <li>"auth0" or unspecified (default) - registers Auth0UserUtils</li>
 * <li>"keycloak" - registers KeycloakUserUtils</li>
 * </ul>
 * 
 * <p>This ensures that only one UserUtils implementation is active at a time,
 * preventing conflicts and ensuring proper dependency injection.</p>
 * 
 * @author Kush Parsaniya
 * @since 0.0.1
 * @see UserUtils
 * @see Auth0UserUtils
 * @see KeycloakUserUtils
 */
@AutoConfiguration
public class UserUtilsAutoConfiguration {

    /**
     * Creates and registers an Auth0UserUtils bean.
     * 
     * <p>This bean is registered when the identity provider is configured as "auth0"
     * or when no identity provider is explicitly specified (default behavior).
     * The Auth0UserUtils implementation handles JWT tokens from Auth0 identity provider.</p>
     * 
     * @return a new instance of Auth0UserUtils
     * @see Auth0UserUtils
     */
    @Bean
    @ConditionalOnProperty(name = "identity.provider", havingValue = "auth0", matchIfMissing = true)
    public UserUtils auth0UserUtils() {
        return new Auth0UserUtils();
    }

    /**
     * Creates and registers a KeycloakUserUtils bean.
     * 
     * <p>This bean is registered when the identity provider is explicitly configured
     * as "keycloak". The KeycloakUserUtils implementation handles JWT tokens from
     * Keycloak identity provider.</p>
     * 
     * @return a new instance of KeycloakUserUtils
     * @see KeycloakUserUtils
     */
    @Bean
    @ConditionalOnProperty(name = "identity.provider", havingValue = "keycloak")
    public UserUtils keycloakUserUtils() {
        return new KeycloakUserUtils();
    }
}
