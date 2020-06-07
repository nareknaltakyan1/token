package com.JWT.token.service;

import com.JWT.token.Repository.UserRepository;
import com.JWT.token.config.WebSecurityConfig;
import com.JWT.token.dto.UserDTO;
import com.JWT.token.entity.User;
import com.JWT.token.enums.UserType;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.ArrayList;

@Service
public class UserService implements UserDetailsService {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder bcryptEncoder;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findByUsername(username);
        if (user == null) {
            throw new UsernameNotFoundException("User not found with username: " + username);
        }
        return new org.springframework.security.core.userdetails.User(user.getUsername(), user.getPassword(),
                new ArrayList<>());
    }

    public User save(UserDTO user) {
        User newUser = new User();
        newUser.setUsername(user.getUsername());
        newUser.setPassword(bcryptEncoder.encode(user.getPassword()));
        newUser.setUserType(UserType.USER);

        return userRepository.save(newUser);
    }

    public User getAuthenticatedUser() {
        String userName = WebSecurityConfig.getAuthenticationUsername();
        if (userName != null) {
            return userRepository.findByUsername(userName);
        } else return null;
    }
}