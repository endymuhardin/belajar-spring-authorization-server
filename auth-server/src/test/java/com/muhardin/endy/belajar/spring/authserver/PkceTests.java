package com.muhardin.endy.belajar.spring.authserver;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;

public class PkceTests {
    @Test
    public void testGenerateCodeChallenge() throws Exception {
        String codeVerifier = "EmJ1jTS245HXMu5dDFc36XlEK02FCfT3BAvbvVfBiXSl";
        String codeChallenge = calculateChallenge(codeVerifier);
        System.out.println("Verifier : ["+ codeVerifier +"]");
        System.out.println("Challenge : ["+codeChallenge +"]");
    }

    private String calculateChallenge(String codeVerifier) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] digest = md.digest(codeVerifier.getBytes(StandardCharsets.US_ASCII));
        return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
    }
}
