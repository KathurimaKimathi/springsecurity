package org.hummingbird.springsecurityclient.controller;

import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.hummingbird.springsecurityclient.entity.User;
import org.hummingbird.springsecurityclient.entity.VerificationToken;
import org.hummingbird.springsecurityclient.event.RegistrationCompleteEvent;
import org.hummingbird.springsecurityclient.model.PasswordModel;
import org.hummingbird.springsecurityclient.model.UserModel;
import org.hummingbird.springsecurityclient.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

import java.util.Optional;
import java.util.UUID;

@RestController
@Slf4j
public class RegistrationController {

    @Autowired
    private UserService userService;

    @Autowired
    private ApplicationEventPublisher publisher;

    @PostMapping("/register")
    public String registerUser(@RequestBody UserModel userModel, final HttpServletRequest request) {
        User user = userService.registerUser(userModel);

        // Publish an event to send email on complete registration
        publisher.publishEvent(new RegistrationCompleteEvent(
                user,
                applicationURL(request)
        ));

        return HttpStatus.OK +"\n Registration successful";
    }

    @GetMapping("/verifyRegistrationToken")
    public String verifyRegistration(@RequestParam("token") String token) {
        String result = userService.validateVerificationToken(token);
        if (result.equalsIgnoreCase("Valid token")){
            return "User has been successfully verified";
        }

        return "Unknown user";
    }

    @GetMapping("/resendVerificationToken")
    public String resendVerificationToken(@RequestParam("token") String oldToken, HttpServletRequest request) {
        VerificationToken verificationToken = userService.generateNewVerificationToken(oldToken);
        User user = verificationToken.getUser();
        resendVerificationTokenMail(user, applicationURL(request), verificationToken);
        return "Verification link sent!";
    }

    @PostMapping("/resetPassword")
    public String resetPassword(@RequestBody PasswordModel passwordModel, HttpServletRequest request) {
        User user = userService.findUserByEmail(passwordModel.getEmail());
        String url = "";
        if(user != null){
            String token = UUID.randomUUID().toString();
            userService.createPasswordResetTokenForUser(user , token);
            url = passwordResetTokenMail(user, applicationURL(request), token);
        }

        return url;
    }

    @PostMapping("/savePassword")
    public String savePassword(@RequestParam("token") String token, @RequestBody PasswordModel passwordModel){
        String result = userService.validatePasswordResetToken(token);
        if (!result.equalsIgnoreCase("Valid token")){
            return "Invalid token";
        }

        Optional<User> user = userService.getUserByPasswordResetToken(token);
        if(user.isPresent()){
            userService.changePassword(user.get(), passwordModel.getNewPassword());
            return "Password reset successful";
        } else {
            return "Invalid Token";
        }
    }

    @PostMapping("/changePassword")
    private String changePassword(@RequestBody PasswordModel passwordModel) {
        User user = userService.findUserByEmail(passwordModel.getEmail());
        if(!userService.checkIfOldPasswordIsValid(user, passwordModel.getOldPassword())){
            return "Current password invalid";
        }

        userService.changePassword(user, passwordModel.getNewPassword());
        return "Password change successful";
    }

    private String passwordResetTokenMail(User user, String applicationURL, String token) {
        String url = applicationURL
                + "/savePassword?token="
                +token;

        // Call the sendVerificationToken() method here
        log.info("Click the link to reset your password: {}", url);
        return url;
    }

    private void resendVerificationTokenMail(User user, String applicationURL, VerificationToken verificationToken) {
        String url = applicationURL
                + "/verifyRegistrationToken?token="
                +verificationToken.getToken();

        // Call the sendVerificationToken() method here
        log.info("Click the link to verify your account: {}", url);
    }

    private String applicationURL(HttpServletRequest request) {
        return "http://" +
                request.getServerName() +
                ":" +
                request.getServerPort() +
                request.getContextPath();
    }
}
