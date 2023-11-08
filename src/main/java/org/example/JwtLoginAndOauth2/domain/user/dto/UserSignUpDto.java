package org.example.JwtLoginAndOauth2.domain.user.dto;

import lombok.Getter;
import lombok.NoArgsConstructor;



/* 자체 로그인-회원가입 요청 Dto */
@Getter
@NoArgsConstructor
public class UserSignUpDto {

    private String email;
    private String password;
    private String nickName;
    private int age;
    private String city;

}
