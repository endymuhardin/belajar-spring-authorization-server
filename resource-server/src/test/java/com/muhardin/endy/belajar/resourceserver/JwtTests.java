package com.muhardin.endy.belajar.resourceserver;

import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.text.ParseException;
import java.time.LocalDateTime;
import java.time.ZoneOffset;

import org.junit.jupiter.api.Test;

import com.nimbusds.jose.JOSEObject;


public class JwtTests {

    @Test
    public void stringToJwt() throws ParseException{
        String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE2ODA3MzEwNjgsImlhdCI6MTY4MDY5NTA2OCwiaXNzIjoiaHR0cDovL2dlbmVyYWxpLmNvLmlkIiwibmJmIjoxNjgwNzMxMDY4fQ.wqiYKs7Al3IgNQSm-uwXsGYQOe1pDEE81xcMRhAfaJY";
        JOSEObject jwt = JOSEObject.parse(token);
        assertNotNull(jwt);
        System.out.println(jwt.getPayload());
        Long jwtExpire = (Long) jwt.getPayload().toJSONObject().get("exp");
        System.out.println("Expire time : "+jwtExpire);
        LocalDateTime expire = LocalDateTime.ofEpochSecond(jwtExpire, 0, ZoneOffset.ofHours(7));
        System.out.println("Expire localdatetime : "+expire);
        System.out.println("Apakah sudah expire? "+expire.isBefore(LocalDateTime.now()));
    }    
}
