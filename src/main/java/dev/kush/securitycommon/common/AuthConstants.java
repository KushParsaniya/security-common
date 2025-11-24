package dev.kush.securitycommon.common;

/**
 * Constants for JWT claim names used by different identity providers.
 * 
 * <p>This class defines the claim names used to extract user and company information
 * from JWT tokens issued by various identity providers including Keycloak and Auth0.
 * These constants are used by the UserUtils implementations to access specific
 * claims within the JWT token structure.</p>
 * 
 * <p>Each identity provider may structure their JWT tokens differently, so separate
 * constants are maintained for each provider to ensure proper claim extraction.</p>
 * 
 * @author Kush Parsaniya
 * @since 0.0.1
 */
public class AuthConstants {

    /**
     * Keycloak JWT claim name for the user Email.
     * Used to extract the user's internal ID from Keycloak JWT tokens.
     */
    public static final String KEYCLOAK_EMAIL_CLAIM = "email";

    /**
     * Keycloak JWT claim name for the user ID.
     * Used to extract the user's internal ID from Keycloak JWT tokens.
     */
    public static final String KEYCLOAK_USER_ID_CLAIM = "user_id";
    
    /**
     * Keycloak JWT claim name for the company ID.
     * Used to extract the user's company ID from Keycloak JWT tokens.
     */
    public static final String KEYCLOAK_COMPANY_ID_CLAIM = "company_id";
    
    /**
     * Keycloak JWT claim name for the company name.
     * Used to extract the user's company name from Keycloak JWT tokens.
     */
    public static final String KEYCLOAK_COMPANY_NAME_CLAIM = "company_name";

    /**
     * Keycloak JWT claim name for the user details.
     * This is the parent claim that contains nested user and company information.
     */
    public static final String KEYCLOAK_DETAILS_CLAIM = "details";

    /**
     * Keycloak JWT claim name for the user's roles.
     * Used to extract the user's role information from Keycloak JWT tokens.
     * Typically contains an array of role strings.
     */
    public static final String KEYCLOAK_ROLE_CLAIM = "roles";


    // Auth0 related constants

    /**
     * Auth0 JWT claim name for the user ID.
     * Used to extract the user's internal ID from Auth0 JWT tokens.
     * The claim is nested within the app_metadata structure.
     */
    public static final String AUTH0_USER_ID_CLAIM = "erp_user_id";
    
    /**
     * Auth0 JWT claim name for the company ID.
     * Used to extract the user's company ID from Auth0 JWT tokens.
     * The claim is nested within the app_metadata structure.
     */
    public static final String AUTH0_COMPANY_ID_CLAIM = "company_id";
    
    /**
     * Auth0 JWT claim name for the application metadata.
     * This is the parent claim that contains nested user and company information.
     */
    public static final String AUTH0_APP_METADATA_CLAIM = "details.app_metadata";
    
    /**
     * Auth0 JWT claim name for the company name.
     * Used to extract the user's company name from Auth0 JWT tokens.
     * The claim is nested within the app_metadata structure.
     */
    public static final String AUTH0_COMPANY_NAME_CLAIM = "company_name";
    
    /**
     * Auth0 JWT claim name for the user's email address.
     * Used to extract the user's email from Auth0 JWT tokens.
     */
    public static final String AUTH0_EMAIL_CLAIM = "details.email";
    
    /**
     * Auth0 JWT claim name for the user's roles.
     * Used to extract the user's role information from Auth0 JWT tokens.
     * Typically contains an array of role strings.
     */
    public static final String AUTH0_ROLE_CLAIM = "details.roles";
}
