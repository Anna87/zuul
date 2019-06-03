package com.zuul.java.config;


import lombok.Getter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Getter
@Component
public class JwtConfig {
    @Value("/auth/**")
    private String Uri;

    @Value("Authorization")
    private String header;

    @Value("Bearer ")
    private String prefix;

    @Value("#{24*60*60}")
    private int expiration;

    @Value("JwtSecretKey")
    private String secret;

}
