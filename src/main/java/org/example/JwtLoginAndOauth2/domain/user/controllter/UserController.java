package org.example.JwtLoginAndOauth2.domain.user.controllter;

import lombok.RequiredArgsConstructor;
import org.example.JwtLoginAndOauth2.domain.user.dto.UserSignUpDto;
import org.example.JwtLoginAndOauth2.domain.user.service.UserService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;



@RestController
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;

    /* 회원 가입 */
    @PostMapping("/sign-up")
    public String signUp(@RequestBody UserSignUpDto userSignUpDto) throws Exception {
        userService.signUp(userSignUpDto);
        return "회원가입 성공";
    }

    /* jwt 테스트 */
    @GetMapping("/jwt-test")
    public String jwtTest() {
        return "jwtTest 요청성공";
    }
}
