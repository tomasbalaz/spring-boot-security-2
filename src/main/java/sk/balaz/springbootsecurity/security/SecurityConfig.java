package sk.balaz.springbootsecurity.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import static sk.balaz.springbootsecurity.security.ApplicationRole.*;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(auth ->
                        auth.requestMatchers("/index.html").permitAll()
                                .requestMatchers("/api/**").hasAnyRole(STUDENT.name())
//                                .requestMatchers(HttpMethod.DELETE,"management/api/**").hasAuthority(COURSE_WRITE.getPermission())
//                                .requestMatchers(HttpMethod.POST,"management/api/**").hasAuthority(COURSE_WRITE.getPermission())
//                                .requestMatchers(HttpMethod.PUT,"management/api/**").hasAuthority(COURSE_WRITE.getPermission())
//                                .requestMatchers(HttpMethod.GET, "management/api/**").hasAnyRole(ADMIN.name(), ADMIN_TRAINEE.name())
                                .anyRequest()
                                .authenticated())
                .httpBasic(Customizer.withDefaults());
        return http.build();
    }

    @Bean
    UserDetailsService userDetailsService(PasswordEncoder passwordEncoder) {
        UserDetails anna = User.builder()
                .username("anna")
                .password(passwordEncoder.encode("password"))
//                .roles(STUDENT.name()) //ROLE_STUDENT
                .authorities(STUDENT.getAuthorities())
                .build();

        UserDetails linda = User.builder()
                .username("linda")
                .password(passwordEncoder.encode("password123"))
//                .roles(ADMIN.name()) //ROLE_ADMIN
                .authorities(ADMIN.getAuthorities())
                .build();

        UserDetails tom = User.builder()
                .username("tom")
                .password(passwordEncoder.encode("password123"))
//                .roles(ADMIN_TRAINEE.name()) //ROLE_ADMIN_TRAINEE
                .authorities(ADMIN_TRAINEE.getAuthorities())
                .build();

        return new InMemoryUserDetailsManager(anna, linda, tom);
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(10);
    }
}
