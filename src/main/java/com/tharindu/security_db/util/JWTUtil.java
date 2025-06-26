package com.tharindu.security_db.util;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.Set;

public class JWTUtil {
    private static final String JWT_SECRET = "WhatTheFuckIsThisSecretKeyBitch";
    private static final SecretKey SECRET_KEY = Keys.hmacShaKeyFor(JWT_SECRET.getBytes(StandardCharsets.UTF_8));
    private static final long EXPIRATION_TIME = (long) 6.048e+8; // 7 days in milliseconds
    // private static final double TOKEN_VALIDITY_TIME = 6.048e+8; // 7 days in milliseconds

    public static String generateToken(String username, Set<String> roles) {
      return Jwts.builder()
                .subject(username)
                .claim("roles", roles)
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + EXPIRATION_TIME))
                .signWith(SECRET_KEY,Jwts.SIG.HS256)
                .compact();
    }

    public static Jws<Claims> parseToken(String token) throws JwtException{
        return Jwts.parser()
                .verifyWith(SECRET_KEY)
                .build()
                .parseSignedClaims(token);
    }

}
