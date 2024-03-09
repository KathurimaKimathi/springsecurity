package org.hummingbird.springsecurityclient.service;

import org.hummingbird.springsecurityclient.entity.User;
import org.hummingbird.springsecurityclient.entity.VerificationToken;
import org.hummingbird.springsecurityclient.model.UserModel;

import java.util.Optional;

public interface UserService {
    User registerUser(UserModel userModel);

    void saveUserVerificationToken(String token, User user);

    String validateVerificationToken(String token);

    VerificationToken generateNewVerificationToken(String oldToken);

    User findUserByEmail(String email);

    void createPasswordResetTokenForUser(User user, String token);

    String validatePasswordResetToken(String token);


    Optional<User> getUserByPasswordResetToken(String token);

    void changePassword(User user, String newPassword);

    boolean checkIfOldPasswordIsValid(User user, String oldPassword);
}
