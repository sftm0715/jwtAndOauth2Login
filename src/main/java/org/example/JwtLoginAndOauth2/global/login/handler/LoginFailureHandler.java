package org.example.JwtLoginAndOauth2.global.login.handler;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;



/* 커스텀 로그인 필터 통과 X 시, 로그인 실패 처리 핸들러  */
// : SimpleUrlAuthenticationFailureHandler 를 상속 받아서 구현

@Slf4j
public class LoginFailureHandler extends SimpleUrlAuthenticationFailureHandler {

    // 인증 실패 시 호출되는 메서드를 재정의
    // 1. status 설정
    // 2. 글자인코딩 설정
    // 3. 콘텐츠 타입 설정
    // 4. 에러 메세지 설정

    @Override
    public void onAuthenticationFailure (HttpServletRequest request,
                                         HttpServletResponse response,
                                         AuthenticationException exception) throws IOException {

        response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
        response.setCharacterEncoding("UTF-8");
        response.setContentType("text/plain;charset=UTF-8");
        response.getWriter().write("로그인 실패! 이메일이나 비밀번호를 확인해주세요.");

        // [exception.getMessage()]"를 출력
        log.info("로그인에 실패했습니다. 메세지 : {}", exception.getMessage());
    }
}
