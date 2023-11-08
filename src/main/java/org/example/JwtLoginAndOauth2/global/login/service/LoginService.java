package org.example.JwtLoginAndOauth2.global.login.service;

import lombok.RequiredArgsConstructor;
import org.example.JwtLoginAndOauth2.domain.user.entity.User;
import org.example.JwtLoginAndOauth2.domain.user.repository.UserRepository;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;






/* 커스텀 로그인 서비스 */
// SecurityConfig에서 AuthenticationManager 빈 등록 시 필요
// DB에서 email 조회 후, 존재하면 Spring Security의 UserDetials(사용자정보 담는 객체) 생성
@Service
@RequiredArgsConstructor
public class LoginService implements UserDetailsService {

    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {

        // 1. UserRepository 를 사용하여 데이터베이스에서 사용자를 이메일 조회후, user로 저장
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("해당 이메일이 존재하지 않습니다."));

        // 2. 이메일 존재 시, user를 통해 Spring Security의 UserDetails(사용자정보를 담는 객체) 생성
        return org.springframework.security.core.userdetails.User.builder()
                .username(user.getEmail())
                .password(user.getPassword())
                .roles(user.getRole().name())
                .build();
    }
}
