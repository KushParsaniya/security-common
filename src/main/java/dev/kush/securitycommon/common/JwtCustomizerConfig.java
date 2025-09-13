package dev.kush.securitycommon.common;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.proc.DefaultJOSEObjectTypeVerifier;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.security.oauth2.resource.servlet.JwkSetUriJwtDecoderBuilderCustomizer;
import org.springframework.context.annotation.Bean;

@AutoConfiguration
public class JwtCustomizerConfig {

    @Bean
    @ConditionalOnProperty(name = "identity.provider", havingValue = "auth0", matchIfMissing = true)
    public JwkSetUriJwtDecoderBuilderCustomizer customizer() {
        return builder -> builder.jwtProcessorCustomizer(processor ->
            processor.setJWSTypeVerifier(new DefaultJOSEObjectTypeVerifier<>(new JOSEObjectType("at+jwt")))
        );
    }
}