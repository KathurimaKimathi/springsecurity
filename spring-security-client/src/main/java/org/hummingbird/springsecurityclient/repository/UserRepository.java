package org.hummingbird.springsecurityclient.repository;

import org.hummingbird.springsecurityclient.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<User, Long> {
    User findByEmail(String email);
}
