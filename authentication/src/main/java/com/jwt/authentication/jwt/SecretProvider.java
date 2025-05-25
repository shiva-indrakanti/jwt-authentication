package com.jwt.authentication.jwt;

import com.jwt.authentication.jwt.utils.JwtUtils;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import java.security.SecureRandom;

@Component
public class SecretProvider {
    private byte[] secretKey;
    private static final Logger LOGGER = LoggerFactory.getLogger(SecretProvider.class);

    @PostConstruct
    public void init(){
        secretKey = new byte[32];
        new SecureRandom().nextBytes(secretKey);
        LOGGER.info("Secret-Key = {}", JwtUtils.base64UrlEncode(secretKey));
    }

    public byte[] getSecretKey() {
        return secretKey;
    }

    public void setSecretKey(byte[] secretKey) {
        this.secretKey = secretKey;
    }
}
