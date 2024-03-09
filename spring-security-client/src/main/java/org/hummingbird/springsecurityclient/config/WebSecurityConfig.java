package org.hummingbird.springsecurityclient.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig {

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(11);
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .csrf().disable() // Disable CSRF
                .authorizeHttpRequests(request -> request
                        .requestMatchers(new AntPathRequestMatcher("/hello"))
                        .permitAll()
                        .requestMatchers(new AntPathRequestMatcher("/register"))
                        .permitAll()
                        .requestMatchers(new AntPathRequestMatcher("/verifyRegistrationToken"))
                        .permitAll()
                        .requestMatchers(new AntPathRequestMatcher("/resendVerificationToken"))
                        .permitAll()
                        .requestMatchers(new AntPathRequestMatcher("/resetPassword"))
                        .permitAll()
                        .requestMatchers(new AntPathRequestMatcher("/savePassword"))
                        .permitAll()
                        .requestMatchers(new AntPathRequestMatcher("/changePassword"))
                        .permitAll());
        return http.build();
    }
}
