package dev.kush.securitycommon.common;

/**
 * Interface for retrieving current user and company information from JWT tokens.
 * 
 * <p>This interface provides methods to extract user-related data from the security context,
 * specifically from JWT tokens that contain authentication and authorization information.
 * Implementations support different identity providers like Auth0 and Keycloak.</p>
 * 
 * <p>All methods in this interface retrieve information from the currently authenticated
 * user's JWT token via the Spring Security context.</p>
 * 
 * @author Kush Parsaniya
 * @since 0.0.1
 */
public interface UserUtils {
    
    /**
     * Retrieves the email address of the currently authenticated user.
     * 
     * @return the user's email address from the JWT token, or null if not available
     */
    String getCurrentUserEmail();

    /**
     * Retrieves the subject identifier of the currently authenticated user.
     * 
     * <p>The subject ID is typically a unique identifier for the user within
     * the identity provider's system.</p>
     * 
     * @return the user's subject ID from the JWT token, or null if not available
     */
    String getCurrentUserSubjectId();

    /**
     * Retrieves the internal user ID of the currently authenticated user.
     * 
     * <p>This is typically the user's ID in the application's database,
     * stored in the JWT token's custom claims.</p>
     * 
     * @return the user's internal ID, or 0L if not available or on error
     */
    Long getCurrentUserId();

    /**
     * Retrieves the company ID associated with the currently authenticated user.
     * 
     * <p>This represents the organization or company that the user belongs to,
     * stored in the JWT token's custom claims.</p>
     * 
     * @return the user's company ID, or 0L if not available or on error
     */
    Long getCurrentCompanyId();

    /**
     * Retrieves the company name associated with the currently authenticated user.
     * 
     * <p>This represents the name of the organization or company that the user belongs to,
     * stored in the JWT token's custom claims.</p>
     * 
     * @return the user's company name, or empty string if not available
     */
    String getCurrentCompanyName();

    /**
     * Retrieves the role of the currently authenticated user.
     * 
     * <p>This represents the user's role or permission level within their organization,
     * stored in the JWT token's custom claims. If multiple roles are present,
     * typically returns the first one.</p>
     * 
     * @return the user's role, or empty string if not available
     */
    String getCurrentUserRole();
}
