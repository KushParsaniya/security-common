package dev.kush.securitycommon.common;

import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Map;

@Component
public class Auth0UserUtils implements UserUtils {

    @Override
    public String getCurrentUserEmail() {
        Jwt jwt = (Jwt) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        return jwt.getClaimAsString(AuthConstants.AUTH0_EMAIL_CLAIM);
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
            detailsMap = jwt.getClaimAsMap(AuthConstants.AUTH0_APP_METADATA_CLAIM);
            if (detailsMap == null) {
                return 0L;
            }
        } catch (Exception e) {
            return 0L;
        }
        return Long.parseLong(detailsMap.get(AuthConstants.AUTH0_USER_ID_CLAIM).toString());
    }

    @Override
    public Long getCurrentCompanyId() {
        Jwt jwt = (Jwt) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        final Map<String, Object> detailsMap = jwt.getClaimAsMap(AuthConstants.AUTH0_APP_METADATA_CLAIM);
        if (detailsMap == null) {
            return 0L;
        }
        return Long.parseLong(detailsMap.get(AuthConstants.AUTH0_COMPANY_ID_CLAIM).toString());
    }

    @Override
    public String getCurrentCompanyName() {
        Jwt jwt = (Jwt) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        final Map<String, Object> detailsMap = jwt.getClaimAsMap(AuthConstants.AUTH0_APP_METADATA_CLAIM);
        if (detailsMap == null) {
            return "";
        }
        return detailsMap.getOrDefault(AuthConstants.AUTH0_COMPANY_NAME_CLAIM, "").toString();
    }

    @Override
    public String getCurrentUserRole() {
        Jwt jwt = (Jwt) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        List<String> roles = jwt.getClaimAsStringList(AuthConstants.AUTH0_ROLE_CLAIM);

        if(roles == null || roles.isEmpty()){
            return "";
        }
        return roles.getFirst();
    }
}
