package sk.balaz.springbootsecurity.auth;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

import static sk.balaz.springbootsecurity.security.ApplicationRole.*;

@Repository("fake")
public class FakeApplicationUserDaoService implements ApplicationUserDao {

    private final PasswordEncoder passwordEncoder;

    public FakeApplicationUserDaoService(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public Optional<ApplicationUser> loadUserByUsername(String username) {
        return getApplicationUsers()
                .stream()
                .filter(applicationUser ->  username.equals(applicationUser.getUsername()))
                .findFirst();
    }

    private List<ApplicationUser> getApplicationUsers() {
        return List.of(
                new ApplicationUser(STUDENT.getAuthorities(),
                        passwordEncoder.encode("password"),
                        "anna",
                        true,
                        true,
                        true,
                        true
                ),
                new ApplicationUser(ADMIN.getAuthorities(),
                        passwordEncoder.encode("password123"),
                        "linda",
                        true,
                        true,
                        true,
                        true
                ),
                new ApplicationUser(ADMIN_TRAINEE.getAuthorities(),
                        passwordEncoder.encode("password123"),
                        "tom",
                        true,
                        true,
                        true,
                        true
                )
        );
    }
}
