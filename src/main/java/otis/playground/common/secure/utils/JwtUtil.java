package otis.playground.common.secure.utils;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.Password;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import otis.playground.common.secure.model.UserPrinciple;
import otis.playground.common.secure.preference.ConfigPreference;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import static otis.playground.common.secure.preference.ConstantPreference.*;

@Component
public class JwtUtil {
    private static final Logger logger = LoggerFactory.getLogger(JwtUtil.class);

    private final ConfigPreference configPreference;

    @Autowired
    public JwtUtil(ConfigPreference configPreference) {
        this.configPreference = configPreference;
    }

    private Password key() {
        return Keys.password(configPreference.jwtSecret.toCharArray());
    }

    public String generateToken(String username, String id, String ip, String agent, UserPrinciple userPrinciple) {
        return Jwts.builder()
                .id(id)
                .subject(username)
                .claim(IP, ip)
                .claim(AGENT, agent)
                .claim(PRINCIPAL, userPrinciple)
                .issuedAt(new Date())
                .expiration(new Date((new Date()).getTime() + configPreference.jwtExpirationMs))
                .encryptWith(key(), Jwts.KEY.PBES2_HS512_A256KW, Jwts.ENC.A256GCM)
                .compact();
    }

    public Map<String, Object> parseToken(String token) {
        try {
            Claims body = Jwts.parser()
                    .decryptWith(key())
                    .build()
                    .parseEncryptedClaims(token)
                    .getPayload();

            Map<String, Object> objectMap = new HashMap<>();
            objectMap.put(IP, body.get(IP));
            objectMap.put(AGENT, body.get(AGENT));
            objectMap.put(PRINCIPAL, body.get(PRINCIPAL));

            return objectMap;
        } catch (Exception e) {
            return null;
        }
    }

    public boolean validateJwtToken(String token) {
        try {
            Jwts.parser().decryptWith(key()).build().parse(token);

            return true;
        } catch (MalformedJwtException e) {
            logger.error("Invalid JWT token: {}", e.getMessage());
        } catch (ExpiredJwtException e) {
            logger.error("JWT token is expired: {}", e.getMessage());
        } catch (UnsupportedJwtException e) {
            logger.error("JWT token is unsupported: {}", e.getMessage());
        } catch (IllegalArgumentException e) {
            logger.error("JWT claims string is empty: {}", e.getMessage());
        }

        return false;
    }
}
