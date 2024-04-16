package sk.balaz.springbootsecurity.jwt;

public record UsernameAndPasswordAuthenticationRequest(
        String username,
        String password) { }
