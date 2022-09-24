package com.liang.springsecurityoauth2.util;

import com.alibaba.fastjson.JSON;
import com.liang.springsecurityoauth2.model.User;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.SignatureException;
import io.jsonwebtoken.UnsupportedJwtException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * JWT工具类
 *
 * @author Liang
 * 2022-09-12
 */
@Slf4j
public class JwtTokenUtils {
    public static final String HEADER = "Authorization";
    public static final String TOKEN_PREFIX = "Bearer ";
    private static final String SECRET = "sign";

    // 该JWT的签发者，是否使用是可选的
    private static final String ISS = "Liang";

    private static final Long EXPIRATION = 60 * 60 * 3L; //过期时间3小时

    //创建token
    public static String createToken(String username, Map<String, Object> map) {
        return TOKEN_PREFIX + Jwts.builder()
                .signWith(SignatureAlgorithm.HS512, SECRET)
                .setClaims(map)
                .setIssuer(ISS)
                //  该JWT所面向的用户，是否使用是可选的；
                .setSubject(username)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + EXPIRATION * 1000))
                .compact();
    }

    public static User getUser(String token) {
        Claims body = getTokenBody(token);
        User user = JSON.parseObject(JSON.toJSONString(body), User.class);
        List<SimpleGrantedAuthority> authorities = JSON.parseArray(body.get("authorities", String.class), String.class)
                .stream()
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());
        user.setAuthorities(authorities);
        return user;
    }

    private static Claims getTokenBody(String token) {
        Claims claims = null;
        try {
            claims = Jwts.parser().setSigningKey(SECRET.getBytes(StandardCharsets.UTF_8)).parseClaimsJws(token).getBody();
        } catch (ExpiredJwtException |
                UnsupportedJwtException |
                MalformedJwtException |
                SignatureException |
                IllegalArgumentException e) {
            e.printStackTrace();
        }
        return claims;
    }

    //是否已过期
    public static boolean isExpiration(String token) {
        try {
            return getTokenBody(token).getExpiration().before(new Date());
        } catch (Exception e) {
            System.out.println(e.getMessage());
        }
        return true;
    }
}