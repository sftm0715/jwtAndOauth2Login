package org.example.JwtLoginAndOauth2.domain.user.repository;


import org.example.JwtLoginAndOauth2.domain.user.entity.SocialType;
import org.example.JwtLoginAndOauth2.domain.user.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {

    Optional<User> findByEmail(String email);
    Optional<User> findByNickname(String nickName);
    Optional<User> findByRefreshToken(String refreshToken);
    Optional<User> findBySocialTypeAndSocialId(SocialType socialType,
                                               String socialId);

}
