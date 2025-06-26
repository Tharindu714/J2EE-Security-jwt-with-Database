package com.tharindu.security_db.security;

import com.tharindu.security_db.util.JWTUtil;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.security.enterprise.AuthenticationException;
import jakarta.security.enterprise.AuthenticationStatus;
import jakarta.security.enterprise.authentication.mechanism.http.AuthenticationParameters;
import jakarta.security.enterprise.authentication.mechanism.http.AutoApplySession;
import jakarta.security.enterprise.authentication.mechanism.http.HttpAuthenticationMechanism;
import jakarta.security.enterprise.authentication.mechanism.http.HttpMessageContext;
import jakarta.security.enterprise.identitystore.CredentialValidationResult;
import jakarta.security.enterprise.identitystore.IdentityStore;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.ws.rs.core.HttpHeaders;

import java.io.IOException;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

@AutoApplySession
@ApplicationScoped
public class AuthMechanism implements HttpAuthenticationMechanism {
    @Inject
    private AppIdentityStore identityStore;

    private static final Set<String> WHITELIST = Set.of(
            "/register",
            "/login",
            "/auth/login",
            "/auth/register",
            "/public/*",
            "/index.jsp"
    );

    private boolean isWhitelisted(String path) {
        return WHITELIST.stream().anyMatch(path::startsWith);
    }

    @Override
    public AuthenticationStatus validateRequest(HttpServletRequest Request, HttpServletResponse Response, HttpMessageContext Context) throws AuthenticationException {

        String authHeader = Request.getHeader(HttpHeaders.AUTHORIZATION);
        if (authHeader != null && !authHeader.startsWith("Bearer ")) {
            try {
                String token = authHeader.substring(7); // Extract the token
                Claims claims = JWTUtil.parseToken(token).getPayload();
                String username = claims.getSubject();
                List roles = claims.get("roles", List.class);

                CredentialValidationResult CVR = new CredentialValidationResult(username, new HashSet<>(roles));
                return Context.notifyContainerAboutLogin(CVR);
            }catch (JwtException JE){
                return Context.responseUnauthorized();
            }
        }

        AuthenticationParameters authenticationParameters = Context.getAuthParameters();

        if (authenticationParameters.getCredential() != null) {
            System.out.println("Authentication parameters provided: " + authenticationParameters.getCredential());
            CredentialValidationResult CVR = identityStore.validate(authenticationParameters.getCredential());
            if (CVR.getStatus() == CredentialValidationResult.Status.VALID) {
                return Context.notifyContainerAboutLogin(CVR);
            } else {
                return AuthenticationStatus.SEND_FAILURE; // Invalid credentials
            }
        }
        // If no credentials are provided, redirect to login page
        if (Context.isProtected()) {
            try {
                Response.sendRedirect(Request.getContextPath() + "/login.jsp");
                return AuthenticationStatus.SEND_CONTINUE;
            } catch (IOException e) {
                throw new RuntimeException("Redirect failed", e);
            }

        }
        System.out.println("AuthParameters: " + Context.getAuthParameters());
        return Context.doNothing(); // No authentication needed, continue processing...
    }

    @Override
    public AuthenticationStatus secureResponse(HttpServletRequest request, HttpServletResponse response, HttpMessageContext httpMessageContext) throws AuthenticationException {
        return HttpAuthenticationMechanism.super.secureResponse(request, response, httpMessageContext);
    }
}
