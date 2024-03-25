package sk.balaz.springbootsecurity.security;

import com.google.common.collect.Sets;

import java.util.Set;

import static sk.balaz.springbootsecurity.security.ApplicationPermission.*;

public enum ApplicationRole {
    STUDENT(Sets.newHashSet()),
    ADMIN(Sets.newHashSet(COURSE_READ, COURSE_WRITE, STUDENT_READ, STUDENT_WRITE));

    private final Set<ApplicationPermission> permissions;

    ApplicationRole(Set<ApplicationPermission> permissions) {
        this.permissions = permissions;
    }

    public Set<ApplicationPermission> getPermissions() {
        return permissions;
    }
}
