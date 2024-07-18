package com.api.security.test;

import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.zaproxy.clientapi.core.ClientApi;
import org.zaproxy.clientapi.core.ClientApiException;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureException;

import java.io.IOException;

public class ApiSecurityTestOWASPTool {
    private static final String API_URL = "https://jsonplaceholder.typicode.com/posts";
    private static final String ZAP_ADDRESS = "localhost";
    private static final int ZAP_PORT = 8080;
    private static final String ZAP_API_KEY = "your-zap-api-key"; // Set your OWASP ZAP API key here
    private static final String JWT_SECRET = "password123_secret";   // Set your JWT secret here
    private static final String JWT_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.RLRCaUvRa_ofTtq3KrDN2FRtOI43SOUzK4bqWvi7g3M"; // Set your JWT token here

    public static void main(String[] args) throws IOException, ClientApiException {
        validateJwtToken(JWT_TOKEN);
        testSqlInjection();
        runZapScan();
    }

    private static void validateJwtToken(String token) {
        try {
            Claims claims = Jwts.parser()
                    .setSigningKey(JWT_SECRET.getBytes())
                    .parseClaimsJws(token)
                    .getBody();
            System.out.println("JWT Token is valid. Claims: " + claims);
        } catch (SignatureException e) {
            System.out.println("Invalid JWT Token");
        }
    }

    private static void testSqlInjection() throws IOException {
        String[] payloads = {"' OR '1'='1", "' OR '1'='1' --"};
        for (String payload : payloads) {
            try (CloseableHttpClient httpClient = HttpClients.createDefault()) {
                HttpGet request = new HttpGet(API_URL + "?id=" + payload);
                request.addHeader("Authorization", "Bearer " + JWT_TOKEN); // Add JWT token for authentication
                try (CloseableHttpResponse response = httpClient.execute(request)) {
                    System.out.println("SQL Injection Test with payload: " + payload + " Response: " + response.getStatusLine());
                }
            }
        }
    }

    private static void runZapScan() throws ClientApiException {
        ClientApi api = new ClientApi(ZAP_ADDRESS, ZAP_PORT, ZAP_API_KEY);

        // Start a new session
        api.core.newSession("SecurityTestSession", "true");

        // Directly Active scan the target
        System.out.println("Scanning target : " + API_URL);
        api.ascan.scan(API_URL, "True", "False", null, null, null);

        // Wait for the active scan to complete
        while (true) {
            int status = Integer.parseInt(api.ascan.status("0").toString());
            if (status == 100) {
                break;
            }
            System.out.println("Scan progress: " + status + "%");
            try {
                Thread.sleep(1000);
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        }

        // Print the alerts
        System.out.println("Active scan completed");
        System.out.println("Alerts:");
        System.out.println(api.core.alerts(API_URL, null, null));
    }
}
