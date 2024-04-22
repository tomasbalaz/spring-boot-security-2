package sk.balaz.springbootsecurity.jwt.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "application.jwt")
public record JwtConfig(
        String secretKey,

        String authHeader,

        String tokenPrefix,

        Integer tokenExpirationAfterDays
) { }