package sk.balaz.springbootsecurity.jwt.config;

import io.jsonwebtoken.security.Keys;
import lombok.AllArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import javax.crypto.SecretKey;

@Configuration
@AllArgsConstructor
public class JwtSecretKey {

    private final JwtConfig jwtConfig;

    @Bean
    SecretKey secretKey() {
        return Keys.hmacShaKeyFor(jwtConfig.secretKey().getBytes());
    }
}
