package dev.kush.securitycommon.common;

import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;

import java.util.List;
import java.util.Map;

/**
 * Auth0 implementation of the UserUtils interface.
 *
 * <p>This class provides methods to extract user and company information from
 * Auth0 JWT tokens. It accesses the Spring Security context to retrieve the
 * current user's JWT token and extracts various claims specific to Auth0's
 * token structure.</p>
 *
 * <p>Auth0 JWT tokens typically contain nested claims within the "details.app_metadata"
 * structure, and this implementation handles the extraction of these nested values.</p>
 *
 * <p>This component is automatically registered when Auth0 is the configured
 * identity provider (default configuration).</p>
 *
 * @author Kush Parsaniya
 * @since 0.0.1
 * @see UserUtils
 * @see AuthConstants
 */
public class Auth0UserUtils implements UserUtils {

    /**
     * {@inheritDoc}
     *
     * <p>For Auth0, the email is extracted from the "details.email" claim
     * in the JWT token.</p>
     */
    @Override
    public String getCurrentUserEmail() {
        Jwt jwt = (Jwt) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        return jwt.getClaimAsString(AuthConstants.AUTH0_EMAIL_CLAIM);
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
     * <p>For Auth0, the user ID is extracted from the "erp_user_id" claim within
     * the "details.app_metadata" nested structure. If the app_metadata is not
     * available or an error occurs, returns 0L.</p>
     *
     * @return the user's internal ID, or 0L if not available or on error
     */
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

    /**
     * {@inheritDoc}
     *
     * <p>For Auth0, the company ID is extracted from the "company_id" claim within
     * the "details.app_metadata" nested structure. If the app_metadata is not
     * available, returns 0L.</p>
     *
     * @return the user's company ID, or 0L if not available
     */
    @Override
    public Long getCurrentCompanyId() {
        Jwt jwt = (Jwt) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        final Map<String, Object> detailsMap = jwt.getClaimAsMap(AuthConstants.AUTH0_APP_METADATA_CLAIM);
        if (detailsMap == null) {
            return 0L;
        }
        return Long.parseLong(detailsMap.get(AuthConstants.AUTH0_COMPANY_ID_CLAIM).toString());
    }

    /**
     * {@inheritDoc}
     *
     * <p>For Auth0, the company name is extracted from the "company_name" claim within
     * the "details.app_metadata" nested structure. If the app_metadata is not
     * available or the company name is not set, returns an empty string.</p>
     *
     * @return the user's company name, or empty string if not available
     */
    @Override
    public String getCurrentCompanyName() {
        Jwt jwt = (Jwt) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        final Map<String, Object> detailsMap = jwt.getClaimAsMap(AuthConstants.AUTH0_APP_METADATA_CLAIM);
        if (detailsMap == null) {
            return "";
        }
        return detailsMap.getOrDefault(AuthConstants.AUTH0_COMPANY_NAME_CLAIM, "").toString();
    }

    /**
     * {@inheritDoc}
     *
     * <p>For Auth0, roles are extracted from the "details.roles" claim which
     * contains a list of role strings. This method returns the first role
     * from the list, or an empty string if no roles are available.</p>
     *
     * @return the user's first role, or empty string if no roles are available
     */
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
