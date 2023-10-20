package otis.playground.common.secure.utils;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.stereotype.Component;

import static otis.playground.common.secure.preference.ConstantPreference.AGENT_HEADER;
import static otis.playground.common.secure.preference.ConstantPreference.CLIENT_HEADER;

@Component
public class SecureUtil {
    public String getClientIp(HttpServletRequest request) {
        String remoteAddr = "";

        if (request != null) {
            remoteAddr = request.getHeader(CLIENT_HEADER);

            if (remoteAddr == null || remoteAddr.isEmpty()) {
                remoteAddr = request.getRemoteAddr();
            }
        }

        return remoteAddr;
    }

    public String getUserAgent(HttpServletRequest request) {
        String userAgent = "";

        if (request != null) {
            userAgent = request.getHeader(AGENT_HEADER);
        }

        return userAgent;
    }
}
