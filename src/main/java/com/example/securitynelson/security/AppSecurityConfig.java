package com.example.securitynelson.security;


import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.WebSecurityConfigurer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;

import static com.example.securitynelson.security.ApplicationUserPermission.*;
import static com.example.securitynelson.security.ApplicationUserRole.*;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class AppSecurityConfig extends WebSecurityConfigurerAdapter {

    private final PasswordEncoder passwordEncoder;

    @Autowired
    public AppSecurityConfig(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .csrf().disable()
                .authorizeRequests()
                .antMatchers("/","index", "/css/*", "/js/*").permitAll()
                .antMatchers("/api/**").hasRole(STUDENT.name()) //allows the role to access any and all urls beginning with 'api'
                .antMatchers( "/management/api/**").hasAnyRole(ADMIN.name()) //handles permissions for get requests
                .anyRequest()
                .authenticated()
                .and()
                .formLogin()
                .loginPage("/login")
        ;


    }

    @Override
    @Bean
    protected UserDetailsService userDetailsService() {
         UserDetails annaSmithUser = User.builder()
                .username("annasmith")
                .password(passwordEncoder.encode("password"))
//                .roles(STUDENT.name()) //implemented the ApplicationUserRole as a static import
                .authorities(STUDENT.getGrantedAuthorities()) //attaching the correct authorities to a pArticular user
                .build();

         UserDetails lindaUser = User.builder()
                 .username("linda")
                 .password(passwordEncoder.encode("password"))
//                 .roles(ADMIN.name()) //implemented the ApplicationUserRole as a static import
                 .authorities(ADMIN.getGrantedAuthorities()) //attaching the correct authorities to a perticular user
                 .build();

        UserDetails tomUser = User.builder()
                .username("tom")
                .password(passwordEncoder.encode("password"))
//                .roles(ADMINTRAINEE.name()) //implemented the ApplicationUserRole as a static import
                .authorities(ADMINTRAINEE.getGrantedAuthorities()) //attaching the correct authorities to a perticular user
                .build();

        return new InMemoryUserDetailsManager(
                annaSmithUser,
                lindaUser,
                tomUser
        );
    }
}
