package sk.balaz.springbootsecurity.jwt;

public record UsernameAndPasswordAuthenticationRequest(
        String userName,
        String password) { }
