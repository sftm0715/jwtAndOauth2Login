package org.example.JwtLoginAndOauth2.global.oauth2.userinfo;

import java.util.Map;


/* attributes(유저속성)을 파라미터로 받아 OAuth2 유저 정보를 만드는 객체 */
public abstract class OAuth2UserInfo {


    protected Map<String, Object> attributes; // protected 제어자 : 추상클래스를 상속받는 클래스에서만 사용가능

    /* 소셜 타입별 attributes 을 주입해 OAuth2 유저정보 객체 생성 */
    public OAuth2UserInfo(Map<String, Object> attributes) {
        this.attributes = attributes;
    }

    /* 유저정보 필드를 가져오는 메서드 */
    // : id, 닉네임, 이미지 url 등

    // 소셜 식별 값 : 구글 - "sub", 카카오 - "id", 네이버 - "id"
    public abstract String getId();
    public abstract String getNickname();
    public abstract String getImageUrl();
}
