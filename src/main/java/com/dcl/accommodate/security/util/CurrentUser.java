package com.dcl.accommodate.security.util;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import java.util.Collection;
import java.util.Optional;
import java.util.UUID;

public class CurrentUser {
    public static Optional<Authentication> getAuthentication(){
        return Optional.ofNullable(SecurityContextHolder.getContext().getAuthentication());
    }

    public static Optional<UUID>  getCurrentUserId(){
        return getAuthentication()
                .map(auth ->{
                    String userId = auth.getName();
                    return userId !=null
                            ? UUID.fromString(userId)
                            :null;
                });
    }

    public static void setAuthentication(Object principal, Collection<? extends GrantedAuthority> authorities) {
        Authentication authentication = new UsernamePasswordAuthenticationToken(
                principal,
                null,
                authorities
        );

        SecurityContextHolder.getContext().setAuthentication(authentication);
    }

    public static void clearAuthentication() {
        SecurityContextHolder.clearContext();
    }
}
