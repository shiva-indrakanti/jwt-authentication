package com.jwt.authentication.jwt.utils;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.jwt.authentication.jwt.SecretProvider;
import com.jwt.authentication.service.AuthenticationService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

@Component
public class JwtUtils {
    private static final Logger LOGGER = LoggerFactory.getLogger(AuthenticationService.class);
    private static final ObjectMapper mapper = new ObjectMapper();

    @Autowired
    private SecretProvider secretProvider;

    //encoding
    public static String base64UrlEncode(byte[] input){
        return Base64.getUrlEncoder().withoutPadding().encodeToString(input);
    }

    //generating token
    public String generateToken(String subject, long expInSeconds) throws JsonProcessingException, NoSuchAlgorithmException, InvalidKeyException {
        // Header
        Map<String, String> headers = new HashMap<>();
        headers.put("alg", "HS256");
        headers.put("typ", "JWT");
        String encodedHeader = base64UrlEncode(mapper.writeValueAsBytes(headers));

        // Payload
        long currentTime = System.currentTimeMillis() / 1000;
        long expiryTime = currentTime + expInSeconds;

        Map<String, Object> payload = new HashMap<>();
        payload.put("sub", subject);
        payload.put("iat", currentTime);
        payload.put("exp", expiryTime);
        String encodedPayload = base64UrlEncode(mapper.writeValueAsBytes(payload));
        String headerPayload = encodedHeader + "." + encodedPayload;

        // Signature
        Mac hmac = Mac.getInstance("HmacSHA256");
        hmac.init(new SecretKeySpec(secretProvider.getSecretKey(), "HmacSHA256"));
        byte[] signature = hmac.doFinal(headerPayload.getBytes(StandardCharsets.UTF_8));
        String encodedSignature = base64UrlEncode(signature);
        String token = headerPayload + "." + encodedSignature;
        LOGGER.info("Generated Token = {}", token);
        return token;
    }

}
