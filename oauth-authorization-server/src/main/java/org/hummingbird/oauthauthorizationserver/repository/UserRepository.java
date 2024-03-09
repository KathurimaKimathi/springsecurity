package org.hummingbird.oauthauthorizationserver.repository;

import org.hummingbird.oauthauthorizationserver.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<User, Long> {
    User findByEmail(String email);
}
