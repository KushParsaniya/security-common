package dev.kush.securitycommon.common;

public interface UserUtils {
    String getCurrentUserEmail();

    String getCurrentUserSubjectId();

    Long getCurrentUserId();

    Long getCurrentCompanyId();

    String getCurrentCompanyName();

    String getCurrentUserRole();
}
