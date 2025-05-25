package com.jwt.authentication.dto.response;

public class LoginResponse {
    private String token;
    private final static String tokenType = "Bearer";
    private long expiresIn;
    private long issuedAt;
    private UserDto userDto;

    public LoginResponse(String token, long expiresIn, long issuedAt ,UserDto useDto) {
        this.token = token;
        this.expiresIn = expiresIn;
        this.issuedAt = issuedAt;
        this.userDto = useDto;
    }

    public String getToken() {
        return token;
    }

    public void setToken(String token) {
        this.token = token;
    }

    public long getExpiresIn() {
        return expiresIn;
    }

    public void setExpiresIn(long expiresIn) {
        this.expiresIn = expiresIn;
    }

    public long getIssuedAt() {
        return issuedAt;
    }

    public void setIssuedAt(long issuedAt) {
        this.issuedAt = issuedAt;
    }

    public String getTokenType() {
        return tokenType;
    }

    public UserDto getUserDto() {
        return userDto;
    }

    public void setUserDto(UserDto userDto) {
        this.userDto = userDto;
    }
}
