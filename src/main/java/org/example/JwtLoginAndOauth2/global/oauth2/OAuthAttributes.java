package org.example.JwtLoginAndOauth2.global.oauth2;

import lombok.Builder;
import lombok.Getter;
import org.example.JwtLoginAndOauth2.domain.user.entity.Role;
import org.example.JwtLoginAndOauth2.domain.user.entity.SocialType;
import org.example.JwtLoginAndOauth2.domain.user.entity.User;
import org.example.JwtLoginAndOauth2.global.oauth2.userinfo.GoogleOAuth2UserInfo;
import org.example.JwtLoginAndOauth2.global.oauth2.userinfo.KaKaoOAuth2UserInfo;
import org.example.JwtLoginAndOauth2.global.oauth2.userinfo.NaverOAuth2UserInfo;
import org.example.JwtLoginAndOauth2.global.oauth2.userinfo.OAuth2UserInfo;


import java.util.Map;
import java.util.UUID;



/* 소셜별 유저정보객체(OAuthAttributes)를 분기해 → 유저객체(User)로 만드는 클래스 */

@Getter
public class OAuthAttributes {

    private String nameAttributeKey;        // OAuth2 유저 객체의 키 (PK)
    private OAuth2UserInfo oAuth2UserInfo;  // OAuth2 유저 객체의 값 (유저정보 : 닉네임, 이메일, 프로필사진 등)

    @Builder
    public OAuthAttributes (String nameAttributeKey,
                            OAuth2UserInfo oAuth2UserInfo) {
        this.nameAttributeKey = nameAttributeKey;
        this.oAuth2UserInfo = oAuth2UserInfo;
    }


    /* 1. SocialType 에 맞는 OAuthAttributes 객체 반환 */
    public static OAuthAttributes of(SocialType socialType,
                                     String userNameAttributeName,
                                     Map<String, Object> attributes) {

        // 소셜타입별 of 메소드 실행 : OAuth2 유저 속성 객체(OAuthAttrtibutes) 생성
        if (socialType == SocialType.NAVER) {
            return ofNaver(userNameAttributeName, attributes);
        }
        if (socialType == SocialType.KAKAO) {
            return ofKaKao(userNameAttributeName, attributes);
        }
        return ofGoogle(userNameAttributeName, attributes);
    }


    /* 2. 소셜별 of 메소드 : OAuth2 유저 속성 객체((OAuthAttrtibutes) 생성 */
    // 각각 소셜 로그인 API 제공하는 nameAttributeKey(키), atttributes(값) 저장 후 build

    // 1) 카카오 유저 속성 키·값 객체 생성
    private static OAuthAttributes ofKaKao(String userNameAttributeName,
                                           Map<String, Object> attributes) {
        return OAuthAttributes.builder()
                .nameAttributeKey(userNameAttributeName)
                .oAuth2UserInfo(new KaKaoOAuth2UserInfo(attributes))
                .build();
    }

    // 2) 구글 유저 속성 키·값 객체 생성
    public static OAuthAttributes ofGoogle(String userNameAttributeName,
                                           Map<String, Object> attributes) {
        return OAuthAttributes.builder()
                .nameAttributeKey(userNameAttributeName)
                .oAuth2UserInfo(new GoogleOAuth2UserInfo(attributes))
                .build();
    }

    // 3) 네이버 유저 속성 키·값 객체 생성
    public static OAuthAttributes ofNaver(String userNameAttrivuteName,
                                          Map<String, Object> attributes) {
        return OAuthAttributes.builder()
                .nameAttributeKey(userNameAttrivuteName)
                .oAuth2UserInfo(new NaverOAuth2UserInfo(attributes))
                .build();
    }

    /* 3. OAuthAttributes 가 담긴 User 엔티티 생성 */
    // OAuth2 유저 속성 객체((OAuthAttrtibutes)로 User 엔티티 생성
    public User toEntity (SocialType socialType,
                          OAuth2UserInfo oauth2UserInfo) {

        return User.builder()
                .socialType(socialType)
                .socialId(oauth2UserInfo.getId())
                .email(UUID.randomUUID() + "@socialUser.com")
                .nickname(oauth2UserInfo.getNickname())
                .imageUrl(oauth2UserInfo.getImageUrl())
                .role(Role.GUEST)
                .build();
    }
}
