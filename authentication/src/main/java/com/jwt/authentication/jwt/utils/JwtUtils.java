package com.jwt.authentication.jwt.utils;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
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

    public static byte[] base64UrlDecode(String input){
        return Base64.getUrlDecoder().decode(input);
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
        String encodedHeaderAndPayload = encodedHeader + "." + encodedPayload;

        // Signature
        String encodedSignature = signToken(encodedHeaderAndPayload);
        String token = encodedHeaderAndPayload + "." + encodedSignature;
        LOGGER.info("Generated Token = {}", token);
        return token;
    }

    /*
      method is used to verify the token
      parameter-1 : token.
      returns boolean value
    */

    public boolean verifyToken(String token) throws NoSuchAlgorithmException, InvalidKeyException, JsonProcessingException {
        String [] parts = token.split("\\.");
        if(parts.length != 3) return false;

        String header = parts[0];
        String payload = parts[1];
        String signature = parts[2];

        String unsignedToken = header +"."+payload;
        String verifiedSignature = signToken(unsignedToken);

        if(!verifiedSignature.equals(signature)){
            return false;
        }

        String decodedPayload = new String(base64UrlDecode(payload),StandardCharsets.UTF_8);
        LOGGER.info("Debug Decoded payload = "+decodedPayload);
        Map<String,Object> payloadMap = mapper.readValue(decodedPayload,Map.class);
        Object expObj = payloadMap.get("exp");
        if (expObj == null) {
            throw new RuntimeException("'exp' field is missing in token");
        }
        long expiration = ((Number) expObj).longValue();
        long now = System.currentTimeMillis()/1000;
        return now < expiration;
    }

    private String signToken(String data) throws NoSuchAlgorithmException, InvalidKeyException {
        Mac hmac = Mac.getInstance("HmacSHA256");
        hmac.init(new SecretKeySpec(secretProvider.getSecretKey(), "HmacSHA256"));
        byte[] signature = hmac.doFinal(data.getBytes(StandardCharsets.UTF_8));
        return base64UrlEncode(signature);
    }

    public String extractUsername(String token) {
        try {
            // 1. Split the token into 3 parts by '.'
            String[] parts = token.split("\\.");
            if (parts.length < 2) {
                throw new IllegalArgumentException("Invalid JWT token");
            }
            String payloadJson = new String(Base64.getUrlDecoder().decode(parts[1]));
            Map<String,Object> map = mapper.readValue(payloadJson, new TypeReference<HashMap<String,Object>>(){});
            return (String) map.get("sub");
        } catch (Exception e) {
            LOGGER.info("Failed to extract username: " + e.getMessage());
            return null;
        }
    }
}
