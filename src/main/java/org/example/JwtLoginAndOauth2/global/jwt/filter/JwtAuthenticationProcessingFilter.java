package org.example.JwtLoginAndOauth2.global.jwt.filter;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.example.JwtLoginAndOauth2.domain.user.entity.User;
import org.example.JwtLoginAndOauth2.domain.user.repository.UserRepository;
import org.example.JwtLoginAndOauth2.global.jwt.service.JwtService;
import org.example.JwtLoginAndOauth2.global.jwt.util.PasswordUtil;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.core.authority.mapping.NullAuthoritiesMapper;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;



/* Jwt 인증 필터 */
// : "/login" 이외의 URI 요청이 왔을 때 처리하는 필터

// 필터 진입 시,
//  1. 인증 처리 : 액세스 O, 리프레시 X
//  2. 인증 실패 : 액세스 X, 리프레스 X
//  3. 토큰 재발급 : 액세스 X, 리프레시 O

@Slf4j
@RequiredArgsConstructor
public class JwtAuthenticationProcessingFilter extends OncePerRequestFilter {

    private static final String NO_CHECK_URL = "/login";

    private final JwtService jwtService;
    private final UserRepository userRepository;

    private GrantedAuthoritiesMapper authoritiesMapper = new NullAuthoritiesMapper();



//  DoFilterInternal()  오버라이드 -----------------------------
// :  필터 진입시, 인증처리 / 실패 / 토큰 재발급 로직 재설정

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        /* 1. 다음 필터로 : 로그인 요청이 아닌 경우 */
        if (request.getRequestURI().equals(NO_CHECK_URL)) {
            filterChain.doFilter(request, response);
            return;
        }

        /* 2. 인증 관련 필터로 : 리프레시 유효한 경우 */
        String refreshToken = jwtService.extractRefreshToken(request)
                .filter(jwtService::isTokeanValid)
                .orElse(null);

        /* 3-1. (리프레시 null X) 인증 성공/실패 처리 : 리프레시 토큰이 일치하는 경우 */
        // ➔ 리프레시 + 액세스 검사 & 엑세스 재발급
        if (refreshToken != null) {
            checkRefreshTokenAndReIssueAccessToken(response, refreshToken);
            return;
        }

        /* 3-2. (리프레시 null O) 인증 성공/실패 처리 : 리프레시 토큰이 null 경우 */
        // ➔ 엑세스 토큰 검사 & 허가
        if (refreshToken == null) {
            checkAccessTokenAndAuthentication(request, response, filterChain);
        }


    }





    // 인증 처리 ---------------------------------


    /*  유저 인증 허가 */
    public void saveAuthentication(User myUser) {
        String password = myUser.getPassword();
        // 소셜 로그인 유저의 비밀번호 임의로 설정 하여 소셜 로그인 유저도 인증 되도록 설정
        if (password == null) {
            password = PasswordUtil.generateRandomPassword();
        }

        UserDetails userDetailsUser = org.springframework.security.core.userdetails.User.builder()
                .username(myUser.getEmail())
                .password(password)
                .roles(myUser.getRole().name())
                .build();

        Authentication authentication =
                new UsernamePasswordAuthenticationToken(userDetailsUser, null, authoritiesMapper.mapAuthorities(userDetailsUser.getAuthorities()));

        SecurityContextHolder.getContext().setAuthentication(authentication);
    }


    /* 엑세스 토큰 체크 + 유저 인증 허가 */
    public void checkAccessTokenAndAuthentication(HttpServletRequest request,
                                                  HttpServletResponse response,
                                                  FilterChain filterChain) throws ServletException, IOException {

        log.info("checkAccessTokenAndAuthentication() 호출");
        jwtService.extractAccessToken(request)
                .filter(jwtService::isTokeanValid)
                .ifPresent(accessToken -> jwtService.extractEmail(accessToken)
                        .ifPresent(email -> userRepository.findByEmail(email)
                                .ifPresent(this::saveAuthentication)));

        filterChain.doFilter(request, response);
    }






    // 재발급-------------------------------------



    /* 리프레시 토큰 재발급 + DB에 리프레시 토큰 업데이트 */
    private String reIssueRefreshToken(User user) {
        String reIssuedRefreshToken = jwtService.createRefreshToken();
        user.updateRefreshToken(reIssuedRefreshToken);
        userRepository.saveAndFlush(user);
        return reIssuedRefreshToken;
    }


    /* 리프레시 토큰 체크 + 엑세스 & 리프레시 토큰 재발급 */

    public void checkRefreshTokenAndReIssueAccessToken (HttpServletResponse response,
                                                        String refreshToken) {

        userRepository.findByRefreshToken(refreshToken)
                .ifPresent(user -> {
                    String reIssuedRefreshToken = reIssueRefreshToken(user);
                    jwtService.sendAccessAndRefresh(response, jwtService.createAccessToken(user.getEmail()),
                            reIssuedRefreshToken);
                });
    }


}