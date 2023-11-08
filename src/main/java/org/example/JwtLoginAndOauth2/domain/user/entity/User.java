package org.example.JwtLoginAndOauth2.domain.user.entity;

import lombok.*;
import org.springframework.security.crypto.password.PasswordEncoder;

import javax.persistence.*;


@Getter
@NoArgsConstructor (access = AccessLevel.PROTECTED)
@Builder
@Table (name = "USERS")
@AllArgsConstructor
@Entity
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "user_id")
    private Long id;

    private String email;
    private String password;
    private String nickname;
    private String imageUrl;
    private int age;
    private String city;
    private String socialId;
    private String refreshToken;

    @Enumerated(EnumType.STRING)
    private Role role;

    @Enumerated(EnumType.STRING)
    private SocialType socialType; // KAKAO, NAVER, GOOGLE



    //---------------------------------------



    /* 유저 권한 설정 메소드 */
    public void authorizeUser() {
        this.role = Role.USER;
    }


    /* 비번 암호화 메서드 */
    public void passwordEncode(PasswordEncoder passwordEncoder) {
        this.password = passwordEncoder.encode(this.password);
    }


    /*== 유저필드 업데이트 ==*/

    // 닉넴
    public void updateNickname(String nickname) {
        this.nickname = nickname;
    }

    // 나이
    public void updateAge(int age) {
        this.age =age;
    }

    // 도시
    public void updateCity(String city) {
        this.city = city;
    }

    // 비번
    public void updatePassword(String password,
                               PasswordEncoder passwordEncoder) {
        this.password = passwordEncoder.encode(password);
    }

    // 리프레시토큰
    public void updateRefreshToken(String updateRefreshToken) {
        this.refreshToken = refreshToken;
    }

}
