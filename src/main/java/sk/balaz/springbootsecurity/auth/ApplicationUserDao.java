package sk.balaz.springbootsecurity.auth;

import java.util.Optional;

public interface ApplicationUserDao {

    Optional<ApplicationUser> loadUserByUsername(String username);
}
