package com.liang.springsecurityoauth2.controller;

import com.liang.springsecurityoauth2.model.User;
import com.liang.springsecurityoauth2.util.JwtTokenUtils;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;

/**
 * @author Liang
 * 2022-09-14
 */
@RestController
@RequestMapping("/user")
public class UserController {

    @GetMapping("/profile")
    public Object profile(HttpServletRequest request) {
        String authorization = request.getHeader("Authorization");
        String token = authorization.substring(authorization.indexOf("bearer ") + 7);
        User user = JwtTokenUtils.getUser(token);
        return user;
    }
}
