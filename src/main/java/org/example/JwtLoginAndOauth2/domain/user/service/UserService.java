package org.example.JwtLoginAndOauth2.domain.user.service;

import lombok.RequiredArgsConstructor;
import org.example.JwtLoginAndOauth2.domain.user.dto.UserSignUpDto;
import org.example.JwtLoginAndOauth2.domain.user.entity.Role;
import org.example.JwtLoginAndOauth2.domain.user.entity.User;
import org.example.JwtLoginAndOauth2.domain.user.repository.UserRepository;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@RequiredArgsConstructor
@Transactional
@Service
public class UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    /* 회원가입 */
    public void signUp(UserSignUpDto userSignUpDto) throws Exception {

        if (userRepository.findByEmail(userSignUpDto.getEmail()).isPresent()) {
            throw new Exception("이미 존재하는 이메일 입니다.");
        }

        if (userRepository.findByNickname(userSignUpDto.getNickName()).isPresent()) {
            throw new Exception("이미 존재하는 닉네임 입니다.");
        }

        User user = User.builder()
                .email(userSignUpDto.getEmail())
                .password(userSignUpDto.getPassword())
                .nickname(userSignUpDto.getNickName())
                .age(userSignUpDto.getAge())
                .city(userSignUpDto.getCity())
                .role(Role.USER)
                .build();

        user.passwordEncode(passwordEncoder);

        userRepository.save(user);
    }

}
