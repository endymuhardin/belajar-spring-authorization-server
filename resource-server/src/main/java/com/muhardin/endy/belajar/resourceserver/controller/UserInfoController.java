package com.muhardin.endy.belajar.resourceserver.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.HashMap;
import java.util.Map;

@RestController
public class UserInfoController {

    @PreAuthorize("hasAnyAuthority('SCOPE_EDIT_TRANSAKSI')")
    @GetMapping("/userinfo")
    public Map<String, Object> userInfo(Authentication currentUser) {
        Map<String, Object> hasil = new HashMap<>();

        hasil.put("waktu",
                LocalDateTime.now()
                        .format(DateTimeFormatter.ISO_LOCAL_DATE_TIME));
        hasil.put("authentication class", currentUser.getClass().getSimpleName());
        hasil.put("current authentication", currentUser);

        JwtAuthenticationToken currentAuthentication = (JwtAuthenticationToken) currentUser;
        currentAuthentication.getName();


        return hasil;
    }
}
