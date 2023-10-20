package otis.playground.common.secure.preference;

public class ConstantPreference {
    public static final String AUTHENTICATED_HEADER = "x-authenticated-user";
    public static final String CLIENT_HEADER = "X-FORWARDED-FOR";
    public static final String AGENT_HEADER = "User-Agent";
    public static final String CONTENT_TYPE = "application/json";
    public static final String CHAR_ENCODING = "UTF-8";
    public static final String USERNAME = "username";
    public static final String ID = "id";
    public static final String IP = "ip";
    public static final String AGENT = "agent";
    public static final String PRINCIPAL = "principal";
    public static final String INVALID_IP = "Suspicious IP, please use your own token !!!";
    public static final String INVALID_AGENT = "Suspicious Agent, please use your own token !!!";
    public static final String EMPTY_TOKEN = "Authorization header token key is not set, please check the request";
    public static final String INVALID_TOKEN = "Invalid request security information, please re-login or check your request";
    public static final String EMPTY_GROUP = "Group can not be empty for access to this resource";
    public static final String INVALID_GROUP = "Insufficient group, you can not access this resource";
    public static final String EMPTY_ROLE = "Role can not be empty for access to this resource";
    public static final String INVALID_ROLE = "Insufficient role, you can not access this resource";
    public static final String EMPTY_PERMISSION = "Permission can not be empty for access to this resource";
    public static final String INVALID_PERMISSION = "Insufficient permission, you can not access this resource";
}
