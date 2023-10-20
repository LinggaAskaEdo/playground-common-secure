package otis.playground.common.secure.filter;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.micrometer.common.util.StringUtils;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.lang.NonNull;
import org.springframework.stereotype.Component;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.HandlerInterceptor;
import otis.playground.common.secure.annotation.Secured;
import otis.playground.common.secure.model.SecureResponse;
import otis.playground.common.secure.model.UserGroup;
import otis.playground.common.secure.model.UserPrinciple;
import otis.playground.common.secure.model.UserRolePermission;
import otis.playground.common.secure.model.enumeration.EGroup;
import otis.playground.common.secure.model.enumeration.EPermission;
import otis.playground.common.secure.model.enumeration.ERole;
import otis.playground.common.secure.utils.JwtUtil;
import otis.playground.common.secure.utils.SecureUtil;

import java.io.IOException;
import java.util.*;
import java.util.function.Function;
import java.util.stream.Collectors;

import static otis.playground.common.secure.preference.ConstantPreference.*;

@Component
public class AuthenticationFilter implements HandlerInterceptor {
    private final JwtUtil jwtUtil;
    private final SecureUtil secureUtil;

    @Autowired
    public AuthenticationFilter(JwtUtil jwtUtil, SecureUtil secureUtil) {
        this.jwtUtil = jwtUtil;
        this.secureUtil = secureUtil;
    }

    public boolean preHandle(@NonNull HttpServletRequest request, @NonNull HttpServletResponse response, @NonNull Object handler) throws Exception {
        try {
            if (handler instanceof HandlerMethod handlerMethod) {
                Secured secured = handlerMethod.getMethod().getAnnotation(Secured.class);

                if (null != secured) {
                    // @Secured annotation is defined, then request must be validated the accessToken from HTTP Request Header
                    String authorizationHeader = request.getHeader(AUTHENTICATED_HEADER);
                    EGroup[] securedGroups = secured.groups();
                    ERole[] securedRoles = secured.roles();
                    EPermission[] securedPermissions = secured.permissions();

                    if (StringUtils.isBlank(authorizationHeader)) {
                        generateResponse(request, response, EMPTY_TOKEN);

                        return false;
                    }

                    if (!jwtUtil.validateJwtToken(authorizationHeader)) {
                        generateResponse(request, response, INVALID_TOKEN);

                        return false;
                    }

                    // Assume that group, role and permission must be set
                    if (securedGroups.length == 0) {
                        generateResponse(request, response, EMPTY_GROUP);

                        return false;
                    }

                    if (securedRoles.length == 0) {
                        generateResponse(request, response, EMPTY_ROLE);

                        return false;
                    }

                    if (securedPermissions.length == 0) {
                        generateResponse(request, response, EMPTY_PERMISSION);

                        return false;
                    }

                    String remoteAddress = secureUtil.getClientIp(request);
                    String userAgent = secureUtil.getUserAgent(request);

                    Map<String, Object> tokenMap = jwtUtil.parseToken(authorizationHeader);

                    // check ip & agent
                    String ip = (String) tokenMap.get(IP);
                    String agent = (String) tokenMap.get(AGENT);

                    if (!Objects.equals(ip, remoteAddress)) {
                        generateResponse(request, response, INVALID_IP);

                        return false;
                    }

                    if (!Objects.equals(agent, userAgent)) {
                        generateResponse(request, response, INVALID_AGENT);

                        return false;
                    }

                    UserPrinciple userPrinciple = new ObjectMapper().convertValue(tokenMap.get(PRINCIPAL), new TypeReference<>() {});
                    UserGroup userGroup = userPrinciple.getGroup();
                    Set<UserRolePermission> userRolePermissionSet = userGroup.getRolePermissionSet();
                    Map<String, UserRolePermission> userRolePermissionMap = userRolePermissionSet.stream().collect(Collectors.toMap(UserRolePermission::getName, Function.identity()));

                    boolean foundGroup;
                    boolean foundRole = false;
                    String foundRoleName = "";
                    boolean foundPermission = false;

                    // check group
                    if (securedGroups.length == 1 && securedGroups[0] == EGroup.ALL) {
                        foundGroup = true;
                    } else {
                        foundGroup = Arrays.stream(securedGroups).map(EGroup::name).toList().contains(userGroup.getName());
                    }

                    if (!foundGroup) {
                        generateResponse(request, response, INVALID_GROUP);

                        return false;
                    }

                    // check role
                    if (securedRoles.length == 1 && securedRoles[0] == ERole.ALL) {
                        foundRole = true;
                    } else {
                        for (UserRolePermission data : userRolePermissionSet) {
                            if (Arrays.stream(securedRoles).map(Enum::name).toList().contains(data.getName())) {
                                foundRole = true;
                                foundRoleName = data.getName();
                                break;
                            }
                        }
                    }

                    if (!foundRole) {
                        generateResponse(request, response, INVALID_ROLE);

                        return false;
                    }

                    if (securedPermissions.length == 1 && securedPermissions[0] == EPermission.ALL) {
                        foundPermission = true;
                    } else {
                        if (!foundRoleName.equalsIgnoreCase("")) {
                            UserRolePermission userRolePermission = userRolePermissionMap.get(foundRoleName);
                            foundPermission = new HashSet<>(List.of(userRolePermission.getPermissions().toArray())).containsAll(Arrays.stream(securedPermissions).map(Enum::name).toList());
                        } else {
                            for (UserRolePermission data : userRolePermissionSet) {
                                foundPermission = new HashSet<>(List.of(data.getPermissions().toArray())).containsAll(Arrays.stream(securedPermissions).map(Enum::name).toList());
                                break;
                            }
                        }
                    }

                    if (!foundPermission) {
                        generateResponse(request, response, INVALID_PERMISSION);

                        return false;
                    }

                    request.setAttribute(USERNAME, userPrinciple.getUsername());
                    request.setAttribute(ID, userPrinciple.getId());
                }

                return true;
            }
        } catch (Exception e) {
            generateResponse(request, response, e.getMessage());

            return false;
        }

        return true;
    }

    private void generateResponse(HttpServletRequest request, HttpServletResponse response, String message) throws IOException {
        response.setStatus(HttpStatus.UNAUTHORIZED.value());
        response.setContentType(CONTENT_TYPE);
        response.setCharacterEncoding(CHAR_ENCODING);
        response.getWriter().write(new ObjectMapper().writeValueAsString(new SecureResponse(HttpStatus.UNAUTHORIZED.value(), message, request.getRequestURI())));
    }
}
