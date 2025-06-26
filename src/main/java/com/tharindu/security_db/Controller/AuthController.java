package com.tharindu.security_db.Controller;

import com.tharindu.security_db.DTO.Credentials;
import com.tharindu.security_db.service.UserService;
import com.tharindu.security_db.util.JWTUtil;
import jakarta.inject.Inject;
import jakarta.json.Json;
import jakarta.json.JsonObject;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import java.util.Set;

@Path("/auth")
public class AuthController {
    @Inject
    private UserService userService;

    @POST
    @Path("/login")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response login(Credentials credentials) {
        // Logic for handling login
        // This is a placeholder; actual implementation will depend on your authentication mechanism
        if (userService.validate(credentials.getUsername(), credentials.getPassword())) {
            Set<String> roles = userService.getRoles(credentials.getUsername());

            String token = JWTUtil.generateToken(credentials.getUsername(), roles);
            // Create a JSON object to return the token
            JsonObject jsonObject = Json.createObjectBuilder().add("token", token).build();
            return Response.ok(jsonObject).build();
        }
        return Response.status(Response.Status.UNAUTHORIZED).build();
    }

    @POST
    @Path("/register")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response register(String json) {
        // Logic for handling registration
        // This is a placeholder; actual implementation will depend on your user management system
        return Response.ok().build();
    }
}
