package com.tharindu.security_db.servlet;

import jakarta.inject.Inject;
import jakarta.security.enterprise.AuthenticationStatus;
import jakarta.security.enterprise.authentication.mechanism.http.AuthenticationParameters;
import jakarta.security.enterprise.credential.UsernamePasswordCredential;
import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.security.enterprise.SecurityContext;

import java.io.IOException;

@WebServlet("/login")
public class Login extends HttpServlet {
    @Inject
    private SecurityContext securityContext;

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String username = request.getParameter("username");
        String password = request.getParameter("password");

        AuthenticationParameters AUTH_PARAM = AuthenticationParameters.withParams().credential(new UsernamePasswordCredential(username, password));
        AuthenticationStatus AUTH_STATUS = securityContext.authenticate(request, response, AUTH_PARAM);
        System.out.println("Authentication Status: " + AUTH_STATUS);
        if (AUTH_STATUS == AuthenticationStatus.SUCCESS) {
            response.sendRedirect(request.getContextPath() + "/home.jsp");
        }else{
            response.sendRedirect(request.getContextPath() + "/login.jsp");
        }
    }
}
