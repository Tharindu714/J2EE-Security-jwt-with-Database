package com.tharindu.security_db.security;

import com.tharindu.security_db.service.UserService;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.security.enterprise.credential.Credential;
import jakarta.security.enterprise.credential.UsernamePasswordCredential;
import jakarta.security.enterprise.identitystore.CredentialValidationResult;
import jakarta.security.enterprise.identitystore.IdentityStore;

import java.util.Set;

@ApplicationScoped
public class AppIdentityStore implements IdentityStore {

//    @PersistenceContext
//    private EntityManager em;

    @Inject
    private UserService loginService;

    @Override
    public CredentialValidationResult validate(Credential credential) {
        System.out.println("Validating credential: " + credential);
        if (credential instanceof UsernamePasswordCredential) {
            UsernamePasswordCredential UPC = (UsernamePasswordCredential) credential;
            if (loginService.validate(UPC.getCaller(), UPC.getPasswordAsString())) {
                Set<String> roles = loginService.getRoles(UPC.getCaller());

                return new CredentialValidationResult(UPC.getCaller(), roles);
            }
        }
//        return IdentityStore.super.validate(credential);
        return CredentialValidationResult.INVALID_RESULT;
    }
}
