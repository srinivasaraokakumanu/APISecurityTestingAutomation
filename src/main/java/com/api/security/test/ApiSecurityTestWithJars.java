package com.api.security.test;

import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureException;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

public class ApiSecurityTestWithJars {
    private static final String API_URL = "https://jsonplaceholder.typicode.com/posts";
    private static final String JWT_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.RLRCaUvRa_ofTtq3KrDN2FRtOI43SOUzK4bqWvi7g3M";

    public static void main(String[] args) throws IOException {
        validateJwtToken(JWT_TOKEN);
        testSqlInjectionUsingEncode();
        testSqlInjectionUsingHttpPost();
    }

    private static void validateJwtToken(String token) {
        try {
            Claims claims = Jwts.parser()
                    .setSigningKey("password123_secret".getBytes()) // Replace with your JWT secret
                    .parseClaimsJws(token)
                    .getBody();
            System.out.println("JWT Token is valid. Claims: " + claims);
        } catch (SignatureException e) {
            System.out.println("Invalid JWT Token");
        }
    }

    private static void testSqlInjectionUsingEncode() throws IOException {
        String[] payloads = {"' OR '1'='1", "' OR '1'='1' --"};
        for (String payload : payloads) {
            try (CloseableHttpClient httpClient = HttpClients.createDefault()) {
                // Encode the payload to be URL-safe
                String encodedPayload = URLEncoder.encode(payload, StandardCharsets.UTF_8);

                // Construct the URL with the encoded payload
                String url = API_URL + "?id=" + encodedPayload;
                System.out.println(url);

                HttpGet request = new HttpGet(url);
                request.addHeader("Authorization", "Bearer " + JWT_TOKEN);
                try (CloseableHttpResponse response = httpClient.execute(request)) {
                    System.out.println("SQL Injection Test with payload: " + payload + " Response: " + response.getStatusLine());
                }
            }
        }
    }

    private static void testSqlInjectionUsingHttpPost() throws IOException {
        String[] payloads = {"' OR '1'='1", "' OR '1'='1' --"};
        for (String payload : payloads) {
            try (CloseableHttpClient httpClient = HttpClients.createDefault()) {
                HttpPost request = new HttpPost(API_URL);

                // Set the payload directly in the request body
                StringEntity entity = new StringEntity("id=" + payload);
                request.setEntity(entity);

                request.addHeader("Authorization", "Bearer " + JWT_TOKEN);

                try (CloseableHttpResponse response = httpClient.execute(request)) {
                    System.out.println("SQL Injection Test with payload: " + payload + " Response: " + response.getStatusLine());
                }
            }
        }
    }


}
