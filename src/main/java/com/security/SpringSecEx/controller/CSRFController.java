package com.security.SpringSecEx.controller;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class CSRFController {

    @GetMapping("/csrf-token")
    public CsrfToken getCSRFToken(CsrfToken token) {
        return token;
    }

    @GetMapping("/csrf-token-2")
    public CsrfToken getCSRFTokenMethod2(HttpServletRequest request) {
        return (CsrfToken) request.getAttribute("_csrf");
    }
}
