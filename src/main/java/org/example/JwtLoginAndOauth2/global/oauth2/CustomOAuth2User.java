package org.example.JwtLoginAndOauth2.global.oauth2;

import lombok.Getter;
import org.example.JwtLoginAndOauth2.domain.user.entity.Role;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;

import java.util.Collection;
import java.util.Map;

/* 커스텀 OAuth2User 클래스 */
// DefaultOAuth2User 상속한 커스텀 OAuth2User 클래스
// OAuth2User 객체에 email, role 필드를 추가해 커스텀
@Getter
public class CustomOAuth2User extends DefaultOAuth2User {

    private String email;
    private Role role;

    public CustomOAuth2User (Collection <? extends GrantedAuthority> authorities,
                             Map<String, Object> attributes,
                             String nameAttributeKey,
                             String email,
                             Role role) {

        super(authorities, attributes, nameAttributeKey);
        this.email = email;
        this.role = role;
    }

}
