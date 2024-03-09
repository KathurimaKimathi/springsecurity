package org.hummingbird.springsecurityclient.event;

import lombok.Getter;
import lombok.Setter;
import org.hummingbird.springsecurityclient.entity.User;
import org.springframework.context.ApplicationEvent;

@Getter
@Setter
public class RegistrationCompleteEvent extends ApplicationEvent {

    private User user;
    private String applicationURL;

    public RegistrationCompleteEvent(User usr, String applicationUrl) {
        super(usr);

        this.user = usr;
        this.applicationURL = applicationUrl;
    }
}
