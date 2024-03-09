package org.hummingbird.springsecurityclient.entity;

import jakarta.persistence.*;
import lombok.Data;
import lombok.Generated;

@Entity
@Data
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long Id;
    private String firstName;
    private String lastName;
    private String email;

    @Column(length = 60)
    private String password;

    private String role;
    private boolean enabled = false;
}
