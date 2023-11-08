package org.example.JwtLoginAndOauth2.global.oauth2.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.example.JwtLoginAndOauth2.domain.user.entity.SocialType;
import org.example.JwtLoginAndOauth2.domain.user.entity.User;
import org.example.JwtLoginAndOauth2.domain.user.repository.UserRepository;
import org.example.JwtLoginAndOauth2.global.oauth2.CustomOAuth2User;
import org.example.JwtLoginAndOauth2.global.oauth2.OAuthAttributes;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;


import java.util.Collections;
import java.util.Map;

@Slf4j
@Service
@RequiredArgsConstructor
public class CustomOAuth2UserServcice implements OAuth2UserService <OAuth2UserRequest, OAuth2User> {

    private final UserRepository userRepository;

    private static final String NAVER = "naver";
    private static final String KAKAO = "kakao";

    @Override
    public OAuth2User loadUser (OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {


        log.info("CustomOAuth2UserService.loadUser() 실행 : OAuth2 로그인 요청 진입");


        /* 1. OAuth2 에서 가져온 유저 정보 추출 */
        OAuth2UserService <OAuth2UserRequest, OAuth2User> delegate = new DefaultOAuth2UserService();
        OAuth2User oAuth2User = delegate.loadUser(userRequest);

        // 1) 소셜 이름 추출
        // ex) kakao, naver, google
        String registrationId = userRequest.getClientRegistration().getRegistrationId();

        // 2) SocialType 으로 변환
        // ex) registrationId(String) → socialType(SocialType)
        SocialType socialType = getSocialType(registrationId);

        // 3) OAuth2 유저 로그인 정보 키 (PK)
        // : 로그인 키(PK)가 되는 값 추출
        String userNameAttributeName =
                userRequest.getClientRegistration()
                        .getProviderDetails().getUserInfoEndpoint()
                        .getUserNameAttributeName();

        // 4) OAuth2 유저 로그인 속성 (attributes)
        Map<String, Object> attributes = oAuth2User.getAttributes();


        /* 2. 소셜 타입에 따라 OAuthAttributes 객체 생성 */
        // : 소셜별 식별값(id), attributes, 유저 속성
        OAuthAttributes extractAttributes = OAuthAttributes.of(socialType, userNameAttributeName, attributes);


        /* 3. User 객체 생성 후 반환 */
        //
        User createdUser = getUser(extractAttributes, socialType);


        /* 4. CustomOAuth2User 객체 생성 반환 */
        return new CustomOAuth2User(
                Collections.singleton(new SimpleGrantedAuthority(createdUser.getRole().getKey())),
                attributes,
                extractAttributes.getNameAttributeKey(),
                createdUser.getEmail(),
                createdUser.getRole()
        );

    }




    //------------------------------------





    /* getSocialType (String registrationId) 부분 */
    // registrationId : NAVER, KAKAO, GOOGLE
    private SocialType getSocialType (String registrationId) {

        if(NAVER.equals(registrationId)) {
            return SocialType.NAVER;
        }
        if (KAKAO.equals(registrationId)) {
            return SocialType.KAKAO;
        }
        return SocialType.GOOGLE;
    }


    /* getUser (OAuthAttributes attributes, SocialType socialType) 부분 */
    // 식별값(attriubtes.getOauth2UserInfo().getId())을 통해, 회원을 찾아 반환
    private User getUser(OAuthAttributes attributes, SocialType socialType) {

        User findUser =
                userRepository
                        .findBySocialTypeAndSocialId(socialType, attributes.getOAuth2UserInfo().getId())
                        .orElse(null);

        if (findUser == null) {
            return saveUser(attributes, socialType);
        }
        return findUser;
    }


    /* saverUser 부분 */
    private User saveUser (OAuthAttributes attributes, SocialType socialType) {
        User createdUser = attributes.toEntity(socialType, attributes.getOAuth2UserInfo());
        return userRepository.save(createdUser);
    }
}
