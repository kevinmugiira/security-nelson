package com.example.securitynelson.auth;

import java.util.Optional;

public interface ApplicationUserDao {


    // this interface make it very easy to switch across databases
    Optional<ApplicationUser> selectApplicationUserByUsername(String username);
}
