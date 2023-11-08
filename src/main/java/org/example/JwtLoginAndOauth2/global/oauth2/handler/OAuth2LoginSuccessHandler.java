package org.example.JwtLoginAndOauth2.global.oauth2.handler;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.example.JwtLoginAndOauth2.domain.user.entity.Role;
import org.example.JwtLoginAndOauth2.domain.user.repository.UserRepository;
import org.example.JwtLoginAndOauth2.global.jwt.service.JwtService;
import org.example.JwtLoginAndOauth2.global.oauth2.CustomOAuth2User;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

import java.rmi.ServerException;


/* OAuth2 로그인 성공 핸들러 */

@Slf4j
@Component
@RequiredArgsConstructor
public class OAuth2LoginSuccessHandler implements AuthenticationSuccessHandler {


    private final JwtService jwtService;
//    private final UserRepository userRepository;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServerException {

        log.info("OAuth2 Login 성공!");

        try {

            // 1. 인증 객체에서 oAuth2User 로그인 유저
            CustomOAuth2User oAuth2User = (CustomOAuth2User) authentication.getPrincipal();

            // 2. 처음 OAuth2 로그인한 유저일 때 (GUEST) 회원가입 로직
            if (oAuth2User.getRole() == Role.GUEST) {
                String accessToken = jwtService.createAccessToken(oAuth2User.getEmail());        // 엑세스토큰 생성
                response.addHeader(jwtService.getAccessHeader(), "Bearer " + accessToken); // 헤더에 엑세스토큰 싣기
                response.sendRedirect("oauth2/sign-up");                                 // "oauth2/sign-up"(회원가입 추가정보 입력폼)

                jwtService.sendAccessAndRefresh(response, accessToken, null);
            }

            // 3. 이미 OAuth2 로그인했던 유저일 때 (USER) 회원가입 로직
            else {
                loginSuccess(response, oAuth2User);
            }


        } catch (Exception e) {
            throw e;
        }
    }

    /* 로그인 성공 로직 */
    // 1. 엑세스/리프레시 토큰 만들어서 해더에 싣기 & 보내기
    // 2. 엑세스/리프레시 보내기
    // 3. 리프리세 토큰 업데이트
    private void loginSuccess(HttpServletResponse response,
                              CustomOAuth2User oAuth2User) throws IOException {

        String accessToken = jwtService.createAccessToken(oAuth2User.getEmail());
        String refreshToken = jwtService.createRefreshToken();
        response.addHeader(jwtService.getAccessHeader(), "Bearer " + accessToken);
        response.addHeader(jwtService.getRefreshHeader(), "Bearer " + refreshToken);

        jwtService.sendAccessAndRefresh(response, accessToken, refreshToken);
        jwtService.updateRefreshToken(oAuth2User.getEmail(), refreshToken);
    }
}
