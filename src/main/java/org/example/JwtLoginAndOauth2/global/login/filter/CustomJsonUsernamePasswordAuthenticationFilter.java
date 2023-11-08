package org.example.JwtLoginAndOauth2.global.login.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.util.StreamUtils;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Map;



/* 커스텀 JSON 로그인 필터 구현 */
// 이후 SecuirtyConfig에서 빈등록 시,
// 인증 매니저(AuthenticationManger : UserDetailsService로 LoginService 설정), 인증 성공 핸들러(AuthenticationSuccessHandler), 인증 실패 핸들러(AuthenticationFailureHandler) 설정 필요

/* JSON 로그인 방식을 사용하기 위한 커스텀 필터 */
// 필터 커스텀 : Spring Security 기본 제공 Form 로그인 -> JSON 형식의 RequestBody 로그인 방식


public class CustomJsonUsernamePasswordAuthenticationFilter extends AbstractAuthenticationProcessingFilter {

    private static final String DEFAULT_LOGIN_REQUEST_URL = "/login"; // 디폴트 URL : "/login"으로 오는 요청을 처리
    private static final String HTTP_METHOD = "POST";                 // 로그인 방식 : 로그인 HTTP 메소드는 POST
    private static final String CONTENT_TYPE = "application/json";    // 콘텐츠 타입 : JSON 타입의 데이터로 오는 로그인 요청만 처리
    private static final String USERNAME_KEY = "email";               // 이메일(유저네임) 키 : 회원 로그인 시, 이메일 요청 JSON Key : "email"
    private static final String PASSWORD_KEY = "password";            // 비밀번호 키  : 회원 로그인 시, 비밀번호 요청 JSon Key : "password"

    private static final AntPathRequestMatcher DEFAULT_LOGIN_PATH_REQUEST_MATCHER =
            new AntPathRequestMatcher(DEFAULT_LOGIN_REQUEST_URL, HTTP_METHOD);     // "/login" + POST로 요청에 매칭됨.

    private final ObjectMapper objectMapper;


    /* 커스텀 필터가 "/login" URL 이 들어올 시, 작동하도록 설정 */
    public CustomJsonUsernamePasswordAuthenticationFilter(ObjectMapper objectMapper) {
        super(DEFAULT_LOGIN_PATH_REQUEST_MATCHER);
        this.objectMapper = objectMapper;
    }


    /* 인증 처리 메소드 */
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request,
                                                HttpServletResponse response) throws AuthenticationException, IOException {

        // 1. 콘텐츠 타입이 "/login" 이 아닐 경우, 에러 메세지
        if (request.getContentType() == null || !request.getContentType().equals(CONTENT_TYPE)) {
            throw new AuthenticationServiceException("Authentication Content-Type not supported: " + request.getContentType());
        }

        // 2. messagebody(JSON 형식) 반환 : request에서 추출 (StreamUtils 사용)
        String messageBoby = StreamUtils.copyToString(request.getInputStream(), StandardCharsets.UTF_8);

        // 3. JSON -> Map(키:값 형태) 변환·추출 : objectMapper.readValue()로 Map 변환, email/password 로 추출
        Map<String, String> usernamePasswordMap = objectMapper.readValue(messageBoby, Map.class);

        String email = usernamePasswordMap.get(USERNAME_KEY);
        String password = usernamePasswordMap.get(PASSWORD_KEY);


        // 4. email, password 로 인증 토큰 만들기 : UsernamePasswordAuthenticationToken()에  principal(email), credentials(password) 대입
        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(email, password);

        // 5. 인증 성공/실패 처리 : AuthenticationManager().authentication() 에 UsernamePasswordAuthenticationToken 객체 대입 -> 인증 성공/실패 처리
        return this.getAuthenticationManager().authenticate(authenticationToken);
    }
}
