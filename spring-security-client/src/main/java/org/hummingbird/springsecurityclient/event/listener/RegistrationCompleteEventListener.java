package org.hummingbird.springsecurityclient.event.listener;

import lombok.extern.slf4j.Slf4j;
import org.hummingbird.springsecurityclient.entity.User;
import org.hummingbird.springsecurityclient.event.RegistrationCompleteEvent;
import org.hummingbird.springsecurityclient.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationListener;
import org.springframework.stereotype.Component;

import java.util.UUID;

@Component
@Slf4j
public class RegistrationCompleteEventListener implements ApplicationListener<RegistrationCompleteEvent> {

    @Autowired
    private UserService userService;

    @Override
    public void onApplicationEvent(RegistrationCompleteEvent event) {
        // Create verification token for the user with a link to the application
        User user = event.getUser();
        String token = UUID.randomUUID().toString();

        userService.saveUserVerificationToken(token, user);

        // Send an email to the user
        String url = event.getApplicationURL()
                + "/verifyRegistrationToken?token="
                +token;

        // Call the sendVerificationToken() method here
        log.info("Click the link to verify your account: {}", url);

    }
}
