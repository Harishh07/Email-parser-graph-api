package com.example.auth1;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Service;
import org.springframework.http.ResponseEntity;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;
import java.security.SecureRandom;
import java.util.Base64;
import org.springframework.stereotype.Service;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.Map;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import javax.servlet.http.HttpSession;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.SessionAttributes;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.http.HttpStatus;
import org.springframework.web.client.RestTemplate;
import java.io.IOException;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.http.MediaType;
@Service
public class MSADAuthService {

    @Autowired
    private Environment env;

    public String getAccessToken(String clientId, String clientSecret, String redirectUri, String authorizationCode) {

        String tenantId = env.getProperty("spring.security.oauth2.client.registration.azure.tenant-id");
        String tokenEndpoint = String.format("https://login.microsoftonline.com/%s/oauth2/v2.0/token", tenantId);

        // Use RestTemplate for making HTTP requests
        RestTemplate restTemplate = new RestTemplate();

        // Prepare the request body
        MultiValueMap<String, String> requestBody = new LinkedMultiValueMap<>();
        requestBody.add("grant_type", "authorization_code");
        requestBody.add("client_id", clientId);
        requestBody.add("client_secret", clientSecret);
        requestBody.add("code", authorizationCode);
        requestBody.add("redirect_uri", redirectUri);
        requestBody.add("scope", "https://graph.microsoft.com/Mail.Read.Shared");
        
        // Make the request
        ResponseEntity<String> responseEntity = restTemplate.postForEntity(tokenEndpoint, requestBody, String.class);

        if (responseEntity.getStatusCode().is2xxSuccessful()) {
         
            return responseEntity.getBody();
        } else {
  
            return null;
        }

    }

    public String getLoginUrl(String clientId, String redirectUri, String state) {
        String tenantId = env.getProperty("spring.security.oauth2.client.registration.azure.tenant-id");
        String scope = "https://graph.microsoft.com/Mail.Read.Shared";
        String loginEndpoint = String.format("https://login.microsoftonline.com/%s/oauth2/authorize", tenantId);
        return String.format("%s?client_id=%s&response_type=code&redirect_uri=%s&scope=%s&state=%s", loginEndpoint,
                clientId, redirectUri, scope, state);
    }

    public String generateRandomState() {
        // Generate a random state for CSRF protection
        byte[] randomBytes = new byte[24];
        new SecureRandom().nextBytes(randomBytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);
    }

    public String extractAccessToken(String accessToken) {
        ObjectMapper objectMapper = new ObjectMapper();
        JsonNode jsonNode;
        try {
            jsonNode = objectMapper.readTree(accessToken);
            return jsonNode.get("access_token").asText();
        } catch (IOException e) {
            // Handle the exception (e.g., log or throw)
            e.printStackTrace();
            return null;
        }
    }
    

    public ResponseEntity<String> getGraphApiResponse(String graphApiUrl, String accessToken) {
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(accessToken);
        headers.setContentType(MediaType.APPLICATION_JSON);

        HttpEntity<String> entity = new HttpEntity<>(headers);

        // Use RestTemplate for making HTTP requests
        RestTemplate restTemplate = new RestTemplate();

        try {
            // Make the request
            ResponseEntity<String> responseEntity = restTemplate.exchange(
                graphApiUrl,
                HttpMethod.GET,
                entity,
                String.class
            );

            return ResponseEntity
                .status(responseEntity.getStatusCode())
                .contentType(MediaType.APPLICATION_JSON)
                .body(responseEntity.getBody());
        } catch (HttpClientErrorException.Unauthorized unauthorizedException) {
            // Handle 401 Unauthorized error, return an unauthorized response
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("{\"error\": \"Unauthorized request\"}");
        }
    }

}
