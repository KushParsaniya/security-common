package dev.kush.securitycommon.common;

import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;

@AutoConfiguration
public class UserUtilsAutoConfiguration {

    @Bean
    @ConditionalOnProperty(name = "identity.provider", havingValue = "auth0", matchIfMissing = true)
    public UserUtils auth0UserUtils() {
        return new Auth0UserUtils();
    }

    @Bean
    @ConditionalOnProperty(name = "identity.provider", havingValue = "keycloak")
    public UserUtils keycloakUserUtils() {
        return new KeycloakUserUtils();
    }
}
