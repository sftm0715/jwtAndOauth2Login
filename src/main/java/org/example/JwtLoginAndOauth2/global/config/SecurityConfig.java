package org.example.JwtLoginAndOauth2.global.config;


import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.example.JwtLoginAndOauth2.domain.user.repository.UserRepository;
import org.example.JwtLoginAndOauth2.global.jwt.filter.JwtAuthenticationProcessingFilter;
import org.example.JwtLoginAndOauth2.global.jwt.service.JwtService;
import org.example.JwtLoginAndOauth2.global.login.filter.CustomJsonUsernamePasswordAuthenticationFilter;
import org.example.JwtLoginAndOauth2.global.login.handler.LoginFailureHandler;
import org.example.JwtLoginAndOauth2.global.login.handler.LoginSuccessHandler;
import org.example.JwtLoginAndOauth2.global.login.service.LoginService;
import org.example.JwtLoginAndOauth2.global.oauth2.handler.OAuth2LoginFailureHandler;
import org.example.JwtLoginAndOauth2.global.oauth2.handler.OAuth2LoginSuccessHandler;
import org.example.JwtLoginAndOauth2.global.oauth2.service.CustomOAuth2UserServcice;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.logout.LogoutFilter;



@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final LoginService loginService;
    private final JwtService jwtService;
    private final UserRepository userRepository;
    private final ObjectMapper objectMapper;
    private final OAuth2LoginSuccessHandler oAuth2LoginSuccessHandler;
    private final OAuth2LoginFailureHandler oAuth2LoginFailureHandler;
    private final CustomOAuth2UserServcice customOAuth2UserServcice;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {


        /* 1. 로그인 폼 비활성화 */
        http
                .formLogin().disable()  // FormLogin 사용 X
                .httpBasic().disable()  // httpBasic 사용 X
                .csrf().disable()       // csrf 보안 사용 X
                .headers().frameOptions().disable()
                .and()

                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS) // 세션 사용하지 않으므로 STATELESS로 설정
                .and()

                /* 2. URL 별 권한 옵션 */
                .authorizeRequests()
                .antMatchers("/", "/css/**", "/images/**", "/js/**", "/favicon.ico", "/h2-console/**").permitAll()  // 기본 페이지, css, image, js, h2-console 접근 가능
                .antMatchers("/sign-up").permitAll()                                                           // 회원가입 접근 가능
                .anyRequest().authenticated()                                                                             // 위의 경로 외에 인증된 사용자만 접근 가능.
                .and()

                /* 3. 소셜 로그인 설정 */
                .oauth2Login()
                .successHandler(oAuth2LoginSuccessHandler)                                                                // 동의하고 계속하기 눌렀을 때, Handler 설정
                .failureHandler(oAuth2LoginFailureHandler)                                                                // 소셜 로그인 실패 시, 핸들러 설정.
                .userInfoEndpoint().userService(customOAuth2UserServcice);                                                //


        /* 4. 필터 동작 순서 설정 */
        // 스프링 시큐리티 필서 순서 설정
        // 1. LogoutFilter : 로그아웃 필터
        // 2. CustomJsonUsernamePasswordAuthenticationFilter : authenticationManager(loginService), loginSuccessHandler, loginFailureHandler
        // 3. JwtAuthenticationProcessingFilter : "/login" 이외의 URI 요청처리 (필터 진입 시, 인증처리 / 실패 / 토큰 재발급 로직 재설정)
        http.addFilterAfter(customJsonUsernamePasswordAuthenticationFilter(), LogoutFilter.class);
        http.addFilterBefore(jwtAuthenticationProcessingFilter(), CustomJsonUsernamePasswordAuthenticationFilter.class);

        return http.build();
    }





        // 빈 등록 부분 -----------------------------------------





    /* JwtAuthenticationProcessingFilter 빈 등록 */
    // JWT 인증 처리를 담당하는 JWT 인증 필터를 빈으로 등록

    @Bean
    public JwtAuthenticationProcessingFilter jwtAuthenticationProcessingFilter() {

        JwtAuthenticationProcessingFilter jwtAuthenticationProcessingFilter
                = new JwtAuthenticationProcessingFilter(jwtService, userRepository);
        return jwtAuthenticationProcessingFilter;
    }



    /* CustomJsonUsernamePasswordAuthenticationFilter 빈 등록 */
    // 커스텀 필터를 사용하기 위해 만든 '커스텀 JSON 인증 필터' 를 Bean으로 등록
    @Bean
    public CustomJsonUsernamePasswordAuthenticationFilter customJsonUsernamePasswordAuthenticationFilter() {

        CustomJsonUsernamePasswordAuthenticationFilter customJsonUsernamePasswordAuthenticationFilter
                = new CustomJsonUsernamePasswordAuthenticationFilter(objectMapper);

        customJsonUsernamePasswordAuthenticationFilter.setAuthenticationManager(authenticationManager());
        customJsonUsernamePasswordAuthenticationFilter.setAuthenticationSuccessHandler(loginSuccessHandler());
        customJsonUsernamePasswordAuthenticationFilter.setAuthenticationFailureHandler(loginFailureHandler());
        return customJsonUsernamePasswordAuthenticationFilter;
    }


    /* 1-1)  passwordEncoder 빈 등록 */
    // PART2의 Provider에 설정할 PasswordEncoder를 빈 등록
    @Bean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }


    /* 1-2) AuthenticationManager 빈 등록 */
    // 커스텀 필터 빈 등록 코드에서 AuthenticationManager를 설정
    @Bean
    public AuthenticationManager authenticationManager() {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();  // DaoAuthenticationProvider를 사용하여 AuthenticationManager를 생성
        provider.setPasswordEncoder(passwordEncoder());                        // PasswordEncoder를 사용하는 AuthenticationProvider 지정
        provider.setUserDetailsService(loginService);                          // UserDetailsService는 커스텀 LoginService로 등록
        return new ProviderManager(provider);                                  // AuthenticationManager로는 구현체인 ProviderManager 사용
    }


    /* 2-1) : LoginSuccessHandler 빈 등록 */
    // JSON 필터 빈 등록 시에 설정할 핸들러를 먼저 빈으로 등록
    // 이전에 만들어뒀던 LoginSuccessHandler & LoginFailureHandler를 생성하여 반환
    @Bean
    public LoginSuccessHandler loginSuccessHandler() {
        return new LoginSuccessHandler(jwtService, userRepository);
    }


    /* 2-2) : LoginFailureHandler 빈 등록 */
    // JSON 필터 빈 등록 시에 설정할 핸들러를 먼저 빈으로 등록
    // 이전에 만들어뒀던 LoginSuccessHandler & LoginFailureHandler를 생성하여 반환
    @Bean
    public LoginFailureHandler loginFailureHandler() {
        return new LoginFailureHandler();
    }


}
