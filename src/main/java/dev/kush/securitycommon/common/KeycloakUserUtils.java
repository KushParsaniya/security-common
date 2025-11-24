package dev.kush.securitycommon.common;

import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;

import java.util.List;
import java.util.Map;

/**
 * Keycloak implementation of the UserUtils interface.
 *
 * <p>This class provides methods to extract user and company information from
 * Keycloak JWT tokens. It accesses the Spring Security context to retrieve the
 * current user's JWT token and extracts various claims specific to Keycloak's
 * token structure.</p>
 *
 * <p>Similar to Auth0, Keycloak JWT tokens contain nested claims within the
 * "details" structure, and this implementation handles the extraction
 * of these nested values using Keycloak-specific claim names.</p>
 *
 * <p>This component is conditionally registered only when the identity provider
 * is configured as "keycloak" via the "identity.provider" property.</p>
 *
 * @author Kush Parsaniya
 * @since 0.0.1
 * @see UserUtils
 * @see AuthConstants
 */
public class KeycloakUserUtils implements UserUtils {

    /**
     * {@inheritDoc}
     *
     * <p>For Keycloak, the email is extracted from the "details.email" claim
     * in the JWT token.</p>
     */
    @Override
    public String getCurrentUserEmail() {
        Jwt jwt = (Jwt) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        return jwt.getClaimAsString(AuthConstants.KEYCLOAK_EMAIL_CLAIM);
    }

    /**
     * {@inheritDoc}
     *
     * <p>The subject ID is extracted from the standard "sub" claim of the JWT token.</p>
     */
    @Override
    public String getCurrentUserSubjectId() {
        Jwt jwt = (Jwt) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        return jwt.getSubject();
    }

    /**
     * {@inheritDoc}
     *
     * <p>For Keycloak, the user ID is extracted from the "user_id" claim within
     * the "details" nested structure. If the details is not
     * available or an error occurs, returns 0L.</p>
     *
     * @return the user's internal ID, or 0L if not available or on error
     */
    @Override
    public Long getCurrentUserId() {
        Jwt jwt = (Jwt) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        final Map<String, Object> detailsMap = jwt.getClaimAsMap(AuthConstants.KEYCLOAK_DETAILS_CLAIM);
        if (detailsMap == null) {
            return 0L;
        }
        return Long.parseLong(detailsMap.get(AuthConstants.KEYCLOAK_USER_ID_CLAIM).toString());
    }

    /**
     * {@inheritDoc}
     *
     * <p>For Keycloak, the company ID is extracted from the "company_id" claim within
     * the "details" nested structure. If the details is not
     * available, returns 0L.</p>
     *
     * @return the user's company ID, or 0L if not available
     */
    @Override
    public Long getCurrentCompanyId() {
        Jwt jwt = (Jwt) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        final Map<String, Object> detailsMap = jwt.getClaimAsMap(AuthConstants.KEYCLOAK_DETAILS_CLAIM);
        if (detailsMap == null) {
            return 0L;
        }
        return Long.parseLong(detailsMap.get(AuthConstants.KEYCLOAK_COMPANY_ID_CLAIM).toString());
    }

    /**
     * {@inheritDoc}
     *
     * <p>For Keycloak, the company name is extracted from the "company_name" claim within
     * the "details" nested structure. If the details is not
     * available or the company name is not set, returns an empty string.</p>
     *
     * @return the user's company name, or empty string if not available
     */
    @Override
    public String getCurrentCompanyName() {
        Jwt jwt = (Jwt) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        final Map<String, Object> detailsMap = jwt.getClaimAsMap(AuthConstants.KEYCLOAK_DETAILS_CLAIM);
        if (detailsMap == null) {
            return "";
        }
        return detailsMap.getOrDefault(AuthConstants.KEYCLOAK_COMPANY_NAME_CLAIM,"").toString();
    }

    /**
     * {@inheritDoc}
     *
     * <p>For Keycloak, roles are extracted from the "roles" claim which
     * contains a list of role strings. This method returns the first role
     * from the list, or an empty string if no roles are available.</p>
     *
     * @return the user's first role, or empty string if no roles are available
     */
    @Override
    public String getCurrentUserRole() {
        Jwt jwt = (Jwt) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        List<String> roles = jwt.getClaimAsStringList(AuthConstants.KEYCLOAK_ROLE_CLAIM);
        if (roles == null || roles.isEmpty()) {
            return "";
        }
        return roles.stream()
                .filter(role -> !role.startsWith("default-")) // remove all default-* roles
                .findFirst() // pick first non-default role
                .orElse(""); // return empty if nothing left
    }

}
