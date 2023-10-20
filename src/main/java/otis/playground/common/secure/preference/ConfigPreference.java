package otis.playground.common.secure.preference;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
public class ConfigPreference {
    @Value("${app.jwtSecret}")
    public String jwtSecret;

    @Value("${app.jwtExpirationMs}")
    public int jwtExpirationMs;
}
