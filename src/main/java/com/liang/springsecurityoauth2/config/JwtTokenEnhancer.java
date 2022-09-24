package com.liang.springsecurityoauth2.config;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.TypeReference;
import com.liang.springsecurityoauth2.model.User;
import com.liang.springsecurityoauth2.util.JwtTokenUtils;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.TokenEnhancer;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * @author Liang
 * 2022-09-14
 */
@Component
public class JwtTokenEnhancer implements TokenEnhancer {
    @Override
    public OAuth2AccessToken enhance(OAuth2AccessToken accessToken, OAuth2Authentication authentication) {
        DefaultOAuth2AccessToken token = (DefaultOAuth2AccessToken) accessToken;
        User principal = JSON.parseObject(JSON.toJSONString(authentication.getPrincipal()), User.class);
        // 颁发token
        Map<String, Object> claim = JSON.parseObject(JSON.toJSONString(principal), new TypeReference<Map<String, Object>>() {
        });
        List<String> authorities = authentication.getAuthorities().stream().map(GrantedAuthority::getAuthority)
                .collect(Collectors.toList());
        claim.put("authorities", JSON.toJSONString(authorities));
        token.setAdditionalInformation(claim);
        return token;
    }
}
