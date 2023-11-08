package org.example.JwtLoginAndOauth2.global.login.handler;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.example.JwtLoginAndOauth2.domain.user.repository.UserRepository;
import org.example.JwtLoginAndOauth2.global.jwt.service.JwtService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;





/* 커스텀 로그인 필터 통과 O 시, 로그인 성공 처리 핸들러  */
// : SimpleUrlAuthenticationSuccessHandler 를 상속 받아서 구현
@Slf4j
@RequiredArgsConstructor
public class LoginSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    @Value("${jwt.access.expiration}")
    private String accessTokenExpiration;

    private final JwtService jwtService;
    private final UserRepository userRepository;


    /* 인증 성공 시 호출되는 메서드를 재정의 */
    // 1. email, 엑세스/리프레시 토큰 객체 생성 : authenticaiton 으로 email, 엑세스/리프레시 토큰 객체 만들기
    // 2. Response에 엑세스/리프레시 토큰 담아서 보내기 : 커스텀 필터를 통과해 인증처리됐으므로
    // 3. 리프레시 토큰 생성/DB 저장 : 일반 회원가입 시 리프레시토큰 없음("/login"은 jwt 없이 접근 가능하기때문에)
    // 따라서 로그인 성공시, 리프레시 토큰 발급 + DB 저장
    // + 로그 남기기 (about email, 엑세스토큰, 엑세스토큰 만료기한)
    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication) {

        // 1. email, 엑세스/리프레시 토큰 객체 생성 : authenticaiton 으로 email, 엑세스/리프레시 토큰 객체 만들기
        String email = extractUsername(authentication);
        String accessToken = jwtService.createAccessToken(email);
        String refreshToken = jwtService.createRefreshToken();

        // 2. Response에 엑세스/리프레시 토큰 담아서 보내기 : 커스텀 필터를 통과해 인증처리됐으므로 바로 토큰 담아서 응답
        jwtService.sendAccessAndRefresh(response, accessToken, refreshToken);

        // 3. 리프레시 토큰 생성/DB 저장 : 일반 회원가입 시 리프레시토큰 없음("/login"은 jwt 없이 접근 가능하기때문에)
        // 따라서 로그인 성공시, 리프레시 토큰 발급 + DB 저장
        userRepository.findByEmail(email)
                .ifPresent(
                        user -> {
                            user.updateRefreshToken(refreshToken); // 유저 테이블의 RefreshToken Column에 업데이트
                            userRepository.saveAndFlush(user);     // saveAndFlush()로 DB에 반영
                });


        // + 로그 남기기 (about email, 엑세스토큰, 엑세스토큰 만료기한)
        log.info("로그인 성공. 이메일 : {}", email);
        log.info("로그인 성공. 엑세스토큰 : {}", accessToken);
        log.info("엑세스토큰 만료기간 : {}", accessTokenExpiration);

    }

    /* authentication 에서 유저네임(email) 추출 메소드 */
    private String extractUsername(Authentication authentication) {
        UserDetails userDetails = (UserDetails) authentication.getPrincipal();
        return userDetails.getUsername();
    }
}
