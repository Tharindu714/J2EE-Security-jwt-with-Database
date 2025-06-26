package com.tharindu.security_db.service;

import com.tharindu.security_db.Entity.User;
import jakarta.enterprise.context.RequestScoped;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;

import java.util.Set;

@RequestScoped
public class UserService {
    @PersistenceContext
    private EntityManager em;

    public boolean validate(String username, String password) {
        User user = em.find(User.class, username);
        return user != null && user.getPassword().equals(password);
    }

    public Set<String> getRoles(String username) {
        User user = em.find(User.class, username);
        if (user != null) {
            return user.getRoles();
        }
        return Set.of(); // Return an empty set if user not found
    }

    public User getUser(String username) {
        return em.find(User.class, username);
    }
}
