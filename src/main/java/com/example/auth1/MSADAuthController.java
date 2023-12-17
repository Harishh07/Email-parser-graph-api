package com.example.auth1;

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
import jakarta.servlet.http.HttpSession;
import java.io.IOException;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.http.MediaType;

@Controller
@RequestMapping("msad-auth")
@SessionAttributes("accessToken")
public class MSADAuthController {

    @Autowired
    private MSADAuthService authService;

    @Autowired
    private Environment environment;

    @GetMapping("/login")
    public String login(HttpSession session) {
        // Generate a random state and store it in the session
        String oauth2State = authService.generateRandomState();
        session.setAttribute("oauth2State", oauth2State);

        // Construct the login URL with the generated state
        String clientId = environment.getProperty("spring.security.oauth2.client.registration.azure.client-id");
        String redirectUri = environment.getProperty("spring.security.oauth2.client.registration.azure.redirect-uri");
        return "redirect:" + authService.getLoginUrl(clientId, redirectUri, oauth2State);
    }

    @GetMapping("/callback")
    public String handleCallback(@RequestParam("code") String code,
                                 @RequestParam("state") String state,
                                 HttpSession session,
                                 Model model) throws IOException {
        String storedState = (String) session.getAttribute("oauth2State");

        if (storedState == null || !storedState.equals(state)) {
            return "{\"error\": \"Invalid state\"}";
        }

        // Use the code parameter to get the access token
        String clientId = environment.getProperty("spring.security.oauth2.client.registration.azure.client-id");
        String clientSecret = environment.getProperty("spring.security.oauth2.client.registration.azure.client-secret");
        String redirectUri = environment.getProperty("spring.security.oauth2.client.registration.azure.redirect-uri");
        String accessToken = authService.getAccessToken(clientId, clientSecret, redirectUri, code);
        session.setAttribute("accessToken", accessToken);

        return "redirect:/msad-auth/displayuserinfo";
    }

    @GetMapping("/displayuserinfo")
    @ResponseBody
    public ResponseEntity<String> fetchAndDisplayEmails(HttpSession session) {
        // Retrieve the access token from the session
        String accessToken = (String) session.getAttribute("accessToken");

        if (accessToken == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("{\"error\": \"Access token not found\"}");
        }

        String extractAccessToken = authService.extractAccessToken(accessToken);

        // Define the required scope for Microsoft Graph API (e.g., "Mail.Read")
        String scope = "Mail.Read";

        // Make a request to the Microsoft Graph API to fetch emails
        String graphApiUrl = "https://graph.microsoft.com/v1.0/me";
        
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(extractAccessToken);
        headers.set("Scope", scope);  // Add the required scope
        headers.setContentType(MediaType.APPLICATION_JSON);  // Set content type as application/json
        
        System.out.print("ACCESSS: " + extractAccessToken);

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

            // Return the JSON response directly
            return ResponseEntity
                .status(responseEntity.getStatusCode())
                .contentType(MediaType.APPLICATION_JSON)
                .body(responseEntity.getBody());
        } catch (HttpClientErrorException.Unauthorized unauthorizedException) {
            // Handle 401 Unauthorized error, return an unauthorized response
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("{\"error\": \"Unauthorized request\"}");
        }
    }

    @GetMapping("/displayemails")
    @ResponseBody
    public ResponseEntity<String> displayEmails(@RequestParam(name = "subject", required = false) String subject, HttpSession session) {
        // Retrieve the access token from the session
        String accessToken = (String) session.getAttribute("accessToken");

        if (accessToken == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("{\"error\": \"Access token not found\"}");
        }

        String extractAccessToken = authService.extractAccessToken(accessToken);

        // Define the required scope for Microsoft Graph API (e.g., "Mail.Read")
        String scope = "Mail.ReadBasic Mail.Read Mail.ReadWrite Mailbox.Read";

        // Make a request to the Microsoft Graph API to fetch emails
        String graphApiBaseUrl = environment.getProperty("graph.api.base-url");
        String graphApiUrl = graphApiBaseUrl + (subject != null ? "&$filter=contains(subject, '" + subject + "')" : "");
        
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(extractAccessToken);
        headers.set("Scope", scope);  // Add the required scope
        headers.setContentType(MediaType.APPLICATION_JSON);  // Set content type as application/json

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

            // Return the JSON response directly
            return ResponseEntity
                .status(responseEntity.getStatusCode())
                .contentType(MediaType.APPLICATION_JSON)
                .body(responseEntity.getBody());
        } catch (HttpClientErrorException.Unauthorized unauthorizedException) {
            // Handle 401 Unauthorized error, return an unauthorized response
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("{\"error\": \"Unauthorized request\"}");
        } catch (HttpClientErrorException.NotFound notFoundException) {
            // Handle 404 Not Found error, return a response with error details
            String errorDetails = notFoundException.getResponseBodyAsString();
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(errorDetails);
        } catch (Exception e) {
            // Handle other exceptions, return a generic error response
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("{\"error\": \"Internal server error\"}");
        }
    }


}
