package com.muhardin.endy.belajar.spring.authserver;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.password.PasswordEncoder;

@SpringBootTest
public class PasswordEncoderTests {
    @Autowired private PasswordEncoder passwordEncoder;

    @Test
    public void testEncode() {
        String password = "jsapp123";
        String hashedPassword = passwordEncoder.encode(password);
        System.out.println("Hashed password : "+hashedPassword);
    }
}
