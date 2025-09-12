package dev.kush.securitycommon.common;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Map;

@Component
@ConditionalOnProperty(name = "identity.provider", havingValue = "keycloak")
public class KeycloakUserUtils implements UserUtils {
    
    @Override
    public String getCurrentUserEmail() {
        Jwt jwt = (Jwt) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        return jwt.getClaimAsString("details.email");
    }

    @Override
    public String getCurrentUserSubjectId() {
        Jwt jwt = (Jwt) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        return jwt.getSubject();
    }

    @Override
    public Long getCurrentUserId() {
        Map<String, Object> detailsMap;
        try {
            Jwt jwt = (Jwt) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
            detailsMap = jwt.getClaimAsMap("details.app_metadata");
            if (detailsMap == null) {
                return 0L;
            }
        } catch (Exception e) {
            return 0L;
        }
        return Long.parseLong(detailsMap.get(AuthConstants.KEYCLOAK_USER_ID_CLAIM).toString());
    }

    @Override
    public Long getCurrentCompanyId() {
        Jwt jwt = (Jwt) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        final Map<String, Object> detailsMap = jwt.getClaimAsMap("details.app_metadata");
        if (detailsMap == null) {
            return 0L;
        }
        return Long.parseLong(detailsMap.get(AuthConstants.KEYCLOAK_COMPANY_ID_CLAIM).toString());
    }

    @Override
    public String getCurrentCompanyName() {
        Jwt jwt = (Jwt) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        final Map<String, Object> detailsMap = jwt.getClaimAsMap("details.app_metadata");
        if (detailsMap == null) {
            return "";
        }
        return detailsMap.getOrDefault(AuthConstants.KEYCLOAK_COMPANY_NAME_CLAIM, "").toString();
    }

    @Override
    public String getCurrentUserRole() {
        Jwt jwt = (Jwt) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        List<String> roles = jwt.getClaimAsStringList("details.roles");
        if (roles == null || roles.isEmpty()) {
            return "";
        }
        return roles.getFirst();
    }
}
