package com.JWT.token.Component;

import com.JWT.token.Repository.UserRepository;
import com.JWT.token.config.WebSecurityConfig;
import com.JWT.token.entity.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

@Component("sec")
public class RoleSecurity {

    @Autowired
    private UserRepository userRepository;

    public boolean hasRole(String role) {
        String username = WebSecurityConfig.getAuthenticationUsername();
        User user = userRepository.findByUsername(username);
        return (user.getUserType().toString()).equals(role);
    }
}
