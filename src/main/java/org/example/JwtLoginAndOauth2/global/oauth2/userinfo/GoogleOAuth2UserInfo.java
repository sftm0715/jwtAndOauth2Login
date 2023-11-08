package org.example.JwtLoginAndOauth2.global.oauth2.userinfo;

import java.util.Map;


/* Google 유저 정보 Response JSON */

// {
/*        "sub": "식별값", */
/*        "name": "name", */
//        "given_name": "given_name",
/*        "picture": "https//lh3.googleusercontent.com/~~", */
//        "email": "email",
//        "email_verified": true,
//        "locale": "ko"
// }

public class GoogleOAuth2UserInfo extends OAuth2UserInfo {

    public GoogleOAuth2UserInfo (Map<String, Object> attributes) {
        super(attributes);
    }

    // 1. 식별값
    @Override
    public String getId() {
        return (String) attributes.get("sub");
    }

    // 2. 닉네임
    @Override
    public String getNickname() {
        return (String) attributes.get("name");
    }

    // 3. 프로필 URL
    @Override
    public String getImageUrl() {
        return (String) attributes.get("picture");
    }

}
