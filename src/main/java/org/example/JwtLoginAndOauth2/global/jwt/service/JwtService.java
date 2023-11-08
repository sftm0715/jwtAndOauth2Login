package org.example.JwtLoginAndOauth2.global.jwt.service;


import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.example.JwtLoginAndOauth2.domain.user.repository.UserRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Date;
import java.util.Optional;

@Slf4j
@RequiredArgsConstructor
@Getter
@Service
public class JwtService {

    @Value("${jwt.secretKey}")
    private String secretKey;
    @Value("${jwt.access.expiration}")
    private Long accessTokenExpiration;
    @Value("${jwt.refresh.expiration}")
    private Long refreshTokenExpiration;
    @Value("${jwt.access.header}")
    private String accessHeader;
    @Value("${jwt.refresh.header}")
    private String refreshHeader;

    private static final String ACCESS_TOKEN_SUBJECT = "AccessToken";
    private static final String REFRESH_TOKEN_SUBJECT = "RefreshToken";
    private static final String EMAIL_CLAIM = "email";
    private static final String BEARER = "Bearer ";

    private final UserRepository userRepository;



    // 토큰 생성 + 보내기 ------------------------------------

    /* 토큰 생성 */

    public String createAccessToken(String email) {
        Date now = new Date();
        return JWT.create()
                .withSubject(ACCESS_TOKEN_SUBJECT)
                .withExpiresAt(new Date(now.getTime() + accessTokenExpiration))
                .withClaim(EMAIL_CLAIM, email)
                .sign(Algorithm.HMAC512(secretKey));
    }

    public String createRefreshToken() {
        Date now = new Date();
        return JWT.create()
                .withSubject(REFRESH_TOKEN_SUBJECT)
                .withExpiresAt(new Date(now.getTime() + refreshTokenExpiration))
                .sign(Algorithm.HMAC512(secretKey));
    }



    /* 헤더 설정 */
    public void setAccessHeader(HttpServletResponse response,
                                String accessToken) {
        response.setHeader(accessHeader, accessToken);
    }

    public void setRefreshHeader(HttpServletResponse response,
                                 String refreshToken) {
        response.setHeader(refreshHeader, refreshToken);
    }



    /* 헤더 실어 보내기 */

    public void sendAccess(HttpServletResponse response,
                           String accessToken) {
        response.setStatus(HttpServletResponse.SC_OK);
        response.setHeader(accessHeader, accessToken);
        log.info("재발급된 Access Token : {}", accessToken);
    }

    public void sendAccessAndRefresh(HttpServletResponse response,
                                     String accessToken,
                                     String refreshToken) {
        response.setStatus(HttpServletResponse.SC_OK);
        setAccessHeader(response, accessToken);
        setRefreshHeader(response, refreshToken);
        log.info("Access Token, Refresh Token 헤더 설정 완료");

    }




    // 토큰 + 이메일 추출 ------------------------------------

    /* 헤더에서 토큰 추출 */
    public Optional<String> extractRefreshToken(HttpServletRequest request) {
        return Optional.ofNullable(request.getHeader(refreshHeader))
                .filter(refreshToken -> refreshToken.startsWith(BEARER))
                .map(refreshToken -> refreshToken.replace(BEARER, ""));
    }

    public Optional<String> extractAccessToken(HttpServletRequest request) {
        return Optional.ofNullable(request.getHeader(accessHeader))
                .filter(refreshToken -> refreshToken.startsWith(BEARER))
                .map(refreshToken -> refreshToken.replace(BEARER, ""));
    }

    /* 토큰에서 이메일 추출 */

    public Optional<String> extractEmail(String accessToken) {
        try {
            return Optional.ofNullable(
                    JWT.require(Algorithm.HMAC512(secretKey))
                            .build()
                            .verify(accessToken)
                            .getClaim(EMAIL_CLAIM)
                            .asString()
            );

        } catch (Exception e) {
            log.error("엑세스 토큰이 유효하지 않습니다.");
            return Optional.empty();
        }
    }


    // 리프레시 토큰 DB 저장 (업데이트) ----------------

    public void updateRefreshToken(String email,
                                   String refreshToken) {
        userRepository.findByEmail(email)
                .ifPresentOrElse(
                        user -> user.updateRefreshToken(refreshToken),
                        () -> new Exception("일치하는 회원이 없습니다.")
                );
    }



    // 토큰 유효성 검사 + 업데이트 -----------------------

    public boolean isTokeanValid(String token) {
        try {
            JWT.require(Algorithm.HMAC512(secretKey))
                    .build()
                    .verify(token);
            return true;

        } catch (Exception e) {
            log.error("유효하지 않은 토큰 입니다. {}", e.getMessage());
            return false;
        }
    }
}
