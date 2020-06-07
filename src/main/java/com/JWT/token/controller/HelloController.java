package com.JWT.token.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

@RestController
@PreAuthorize("@sec.hasRole('ADMIN')")
public class HelloController {

    @RequestMapping(value = "/hello", method = RequestMethod.POST)
    public ResponseEntity<?> hello() {
        return ResponseEntity.ok("ok");
    }
}
