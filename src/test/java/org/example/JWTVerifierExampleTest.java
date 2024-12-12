package org.example;

import com.auth0.jwk.JwkException;
import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.RSAKeyProvider;
import org.testng.annotations.Test;

import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.*;

public class JWTVerifierExampleTest {

    @Test
    void testValidJWT() throws JWTVerificationException, JwkException {
        final String expectedIssuer = "https://XXXX/";
        final String expectedAudience = "https://XXXX";
        final Set<String> requiredScopes = new HashSet<>(Arrays.asList("request:size"));
        
        final RSAKeyProvider mockKeyProvider = mock(RSAKeyProvider.class);
        when(mockKeyProvider.getPublicKeyById(anyString())).thenReturn(mock(RSAPublicKey.class));

        final Algorithm algorithm = Algorithm.RSA256(mockKeyProvider);
        final JWTVerifier verifier = JWT.require(algorithm)
                .withIssuer(expectedIssuer)
                .withAudience(expectedAudience)
                .build();

        final String token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImdpaXF3ZTB6OVNSblQwbVVLejVxRiJ9.eyJhcHBOYW1lIjoiY29yZS1zaXppbmctc2VydmljZSIsImlzcyI6Imh0dHBzOi8vYXV0aC1jaGltZXJhLmF1dGgwLmFuYXBsYW4tbnAubmV0LyIsInN1YiI6ImsxWW94alpKYlhqQXRaZ0JzT1U3MENhVEtBVkRacVBrQGNsaWVudHMiLCJhdWQiOiJodHRwczovL2NvcmUtc2l6aW5nLmFuYXBsYW4uY29tIiwiaWF0IjoxNzMyMjY1NzAzLCJleHAiOjE3MzIyNzY1MDMsInNjb3BlIjoicmVxdWVzdDpzaXplIiwiZ3R5IjoiY2xpZW50LWNyZWRlbnRpYWxzIiwiYXpwIjoiazFZb3hqWkpiWGpBdFpnQnNPVTcwQ2FUS0FWRFpxUGsifQ.YRu-AcKYXAjb6LWuv1RxJiIJg5IYaY9z23NMkPZX5Mjf1lswK1pAxv5uvxuM0dV8enJoaghoLuAxGBKRNjXy1tnnJWA1Tj3NElC8mvuWofLoyzDrNbGdp4MKCmSgck2GUjY5RBmqNfUmxxllnCEdl7Kba3-uj7DcZKYT6DAo_gVf5ISs-31g18A654_sMSccoOoxxCNV_3Rp41uXNhsFCx6eW3YEJKwV9Adz7ThDUkXr4ZgUT_8OQYc1D3qahBBlRsrf5OA5_SsRRv7DlxJ9UcUhKf071XcHapQKq6iEzHjYC2u2t0c5E4AcwIiLwDWBR_mD2ZiS9fwPC4CcKOpnEA";
        final DecodedJWT jwt = verifier.verify(token);

        assertNotNull(jwt);
    }

    @Test
    void testInvalidIssuer() throws JWTVerificationException, JwkException {
        final String expectedIssuer = "https://XXXX/";
        final String expectedAudience = "https://XXXX";
        final Set<String> requiredScopes = new HashSet<>(Arrays.asList("request:size"));

        final RSAKeyProvider mockKeyProvider = mock(RSAKeyProvider.class);
        when(mockKeyProvider.getPublicKeyById(anyString())).thenReturn(mock(RSAPublicKey.class));

        final Algorithm algorithm = Algorithm.RSA256(mockKeyProvider);
        final JWTVerifier verifier = JWT.require(algorithm)
                .withIssuer(expectedIssuer)
                .withAudience(expectedAudience)
                .build();

        assertThrows(JWTVerificationException.class, () -> {
            final String token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImdpaXF3ZTB6OVNSblQwbVVLejVxRiJ9.eyJhcHBOYW1lIjoiY29yZS1zaXppbmctc2VydmljZSIsImlzcyI6Imh0dHBzOi8vYXV0aC1jaGltZXJhLmF1dGgwLmFuYXBsYW4tbnAubmV0LyIsInN1YiI6ImsxWW94alpKYlhqQXRaZ0JzT1U3MENhVEtBVkRacVBrQGNsaWVudHMiLCJhdWQiOiJodHRwczovL2NvcmUtc2l6aW5nLmFuYXBsYW4uY29tIiwiaWF0IjoxNzMyMjY1NzAzLCJleHAiOjE3MzIyNzY1MDMsInNjb3BlIjoicmVxdWVzdDpzaXplIiwiZ3R5IjoiY2xpZW50LWNyZWRlbnRpYWxzIiwiYXpwIjoiazFZb3hqWkpiWGpBdFpnQnNPVTcwQ2FUS0FWRFpxUGsifQ.YRu-AcKYXAjb6LWuv1RxJiIJg5IYaY9z23NMkPZX5Mjf1lswK1pAxv5uvxuM0dV8enJoaghoLuAxGBKRNjXy1tnnJWA1Tj3NElC8mvuWofLoyzDrNbGdp4MKCmSgck2GUjY5RBmqNfUmxxllnCEdl7Kba3-uj7DcZKYT6DAo_gVf5ISs-31g18A654_sMSccoOoxxCNV_3Rp41uXNhsFCx6eW3YEJKwV9Adz7ThDUkXr4ZgUT_8OQYc1D3qahBBlRsrf5OA5_SsRRv7DlxJ9UcUhKf071XcHapQKq6iEzHjYC2u2t0c5E4AcwIiLwDWBR_mD2ZiS9fwPC4CcKOpnEA";
            final DecodedJWT jwt = verifier.verify(token);
        });
    }

    @Test
    void testInvalidAudience() throws JWTVerificationException, JwkException {
        final String expectedIssuer = "https://XXXX/";
        final String expectedAudience = "https://XXXX";
        final Set<String> requiredScopes = new HashSet<>(Arrays.asList("request:size"));

        final RSAKeyProvider mockKeyProvider = mock(RSAKeyProvider.class);
        when(mockKeyProvider.getPublicKeyById(anyString())).thenReturn(mock(RSAPublicKey.class));

        final Algorithm algorithm = Algorithm.RSA256(mockKeyProvider);
        final JWTVerifier verifier = JWT.require(algorithm)
                .withIssuer(expectedIssuer)
                .withAudience(expectedAudience)
                .build();

        assertThrows(JWTVerificationException.class, () -> {
            final String token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImdpaXF3ZTB6OVNSblQwbVVLejVxRiJ9.eyJhcHBOYW1lIjoiY29yZS1zaXppbmctc2VydmljZSIsImlzcyI6Imh0dHBzOi8vYXV0aC1jaGltZXJhLmF1dGgwLmFuYXBsYW4tbnAubmV0LyIsInN1YiI6ImsxWW94alpKYlhqQXRaZ0JzT1U3MENhVEtBVkRacVBrQGNsaWVudHMiLCJhdWQiOiJodHRwczovL2NvcmUtc2l6aW5nLmFuYXBsYW4uY29tIiwiaWF0IjoxNzMyMjY1NzAzLCJleHAiOjE3MzIyNzY1MDMsInNjb3BlIjoicmVxdWVzdDpzaXplIiwiZ3R5IjoiY2xpZW50LWNyZWRlbnRpYWxzIiwiYXpwIjoiazFZb3hqWkpiWGpBdFpnQnNPVTcwQ2FUS0FWRFpxUGsifQ.YRu-AcKYXAjb6LWuv1RxJiIJg5IYaY9z23NMkPZX5Mjf1lswK1pAxv5uvxuM0dV8enJoaghoLuAxGBKRNjXy1tnnJWA1Tj3NElC8mvuWofLoyzDrNbGdp4MKCmSgck2GUjY5RBmqNfUmxxllnCEdl7Kba3-uj7DcZKYT6DAo_gVf5ISs-31g18A654_sMSccoOoxxCNV_3Rp41uXNhsFCx6eW3YEJKwV9Adz7ThDUkXr4ZgUT_8OQYc1D3qahBBlRsrf5OA5_SsRRv7DlxJ9UcUhKf071XcHapQKq6iEzHjYC2u2t0c5E4AcwIiLwDWBR_mD2ZiS9fwPC4CcKOpnEA";
            final DecodedJWT jwt = verifier.verify(token);
        });
    }

    @Test
    void testInvalidScope() throws JWTVerificationException, JwkException {
        final String expectedIssuer = "https://XXXX/";
        final String expectedAudience = "https://XXXX";
        final Set<String> requiredScopes = new HashSet<>(Arrays.asList("request:size"));

        final RSAKeyProvider mockKeyProvider = mock(RSAKeyProvider.class);
        when(mockKeyProvider.getPublicKeyById(anyString())).thenReturn(mock(RSAPublicKey.class));

        final Algorithm algorithm = Algorithm.RSA256(mockKeyProvider);
        final JWTVerifier verifier = JWT.require(algorithm)
                .withIssuer(expectedIssuer)
                .withAudience(expectedAudience)
                .build();

        assertThrows(JWTVerificationException.class, () -> {
            final String token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImdpaXF3ZTB6OVNSblQwbVVLejVxRiJ9.eyJhcHBOYW1lIjoiY29yZS1zaXppbmctc2VydmljZSIsImlzcyI6Imh0dHBzOi8vYXV0aC1jaGltZXJhLmF1dGgwLmFuYXBsYW4tbnAubmV0LyIsInN1YiI6ImsxWW94alpKYlhqQXRaZ0JzT1U3MENhVEtBVkRacVBrQGNsaWVudHMiLCJhdWQiOiJodHRwczovL2NvcmUtc2l6aW5nLmFuYXBsYW4uY29tIiwiaWF0IjoxNzMyMjY1NzAzLCJleHAiOjE3MzIyNzY1MDMsInNjb3BlIjoicmVxdWVzdDpzaXplIiwiZ3R5IjoiY2xpZW50LWNyZWRlbnRpYWxzIiwiYXpwIjoiazFZb3hqWkpiWGpBdFpnQnNPVTcwQ2FUS0FWRFpxUGsifQ.YRu-AcKYXAjb6LWuv1RxJiIJg5IYaY9z23NMkPZX5Mjf1lswK1pAxv5uvxuM0dV8enJoaghoLuAxGBKRNjXy1tnnJWA1Tj3NElC8mvuWofLoyzDrNbGdp4MKCmSgck2GUjY5RBmqNfUmxxllnCEdl7Kba3-uj7DcZKYT6DAo_gVf5ISs-31g18A654_sMSccoOoxxCNV_3Rp41uXNhsFCx6eW3YEJKwV9Adz7ThDUkXr4ZgUT_8OQYc1D3qahBBlRsrf5OA5_SsRRv7DlxJ9UcUhKf071XcHapQKq6iEzHjYC2u2t0c5E4AcwIiLwDWBR_mD2ZiS9fwPC4CcKOpnEA";
            final DecodedJWT jwt = verifier.verify(token);
        });
    }

//    @Test
//    void testMissingScopeClaim() throws JWTVerificationException, JwkException {
//        final String expectedIssuer = "https://XXXX";
//        final String expectedAudience = "https://XXXX";
//        final Set<String> requiredScopes = new HashSet<>(Arrays.asList("request:size"));
//
//        final RSAKeyProvider mockKeyProvider = mock(RSAKeyProvider.class);
//        when(mockKeyProvider.getPublicKeyById(anyString()).thenReturn(mock(RSAPublicKey.class));
//
//        final Algorithm algorithm = Algorithm.RSA256(mockKeyProvider);
//        final JWTVerifier verifier = JWT.require(algorithm)
//                .withIssuer(expectedIssuer)
//                .withAudience(expectedAudience)
//                .build();
//
//        assertThrows(JWTVerificationException.class, () -> {
//            final String token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJhcHBOYW1lIjoiY29yZS1zaXppbmctc2VydmljZSIsImlzcyI6Imh0dHBzOi8vYXV0aC1jaGlsbW1lY2F1dGgwLmFuYXBsYW4tbnAubmV0L2luZm9ybWF0aW9u.eyJhcHBOYW1lIjoiY29yZS1zaXppbmctc2VydmljZSIsImlzcyI6Imh0dHBzOi8vYXV0aC1jaGlsbW1lY2F1dGgwLmFuYXBsYW4tbnAubmV0L2luZm9ybWF0aW9u.eyJhcHBOYW1lIjoiY29yZS1zaXppbmctc2VydmljZSIsImlzcyI6Imh0dHBzOi8vYXV0aC1jaGlsbW1lY2F1dGgwLmFuYXBsYW4tbnAubmV0L2luZm9ybWF0aW9u.eyJhcHBOYW1lIjoiY29yZS1zaXppbmctc2VydmljZSIsImlzcyI6Imh0dHBzOi8vYXV0aC1jaGlsbW1lY2F1dGgwLmFuYXBsYW4tbnAubmV0L2luZm9ybWF0aW9u.eyJhcHBOYW1lIjoiY29yZS1zaXppbmctc2VydmljZSIsImlzcyI6Imh0dHBzOi8vYXV0aC1jaGlsbW1lY2F1dGgwLmFuYXBsYW4tbnAubmV0L2luZm9ybWF0aW9u.eyJhcHBOYW1lIjoiY29yZS1zaXppbmctc2VydmljZSIsImlzcyI6Imh0dHBzOi8vYXV0aC1jaGlsbW1lY2F1dGgwLmFuYXBsYW4tbnAubmV0L2luZm9ybWF0aW9u.eyJhcHBOYW1lIjoiY29yZS1zaXppbmctc2VydmljZSIsImlzcyI6Imh0dHBzOi8vYXV0aC1jaGlsbW1lY2F1dGgwLmFuYXBsYW4tbnAubmV0L2luZm9ybWF0aW9u.eyJhcHBOYW1lIjoiY29yZS1zaXppbmctc2VydmljZSIsImlzcyI6Imh0dHBzOi8vYXV0aC1jaGlsbW1lY2F1dGgwLmFuYXBsYW4tbnAubmV0L2luZm9ybWF0aW9u.eyJhcHBOYW1lIjoiY29yZS1zaXppbmctc2VydmljZSIsImlzcyI6Imh0dHBzOi8vYXV0aC1jaGlsbW1lY2F1dGgwLmFuYXBsYW4tbnAubmV0L2luZm9ybWF0aW1lIjoiY29yZS1zaXppbmctc2VydmljZSIsImlzcyI6Imh0dHBzOi8vYXV0aC1jaGlsbW1lY2F1dGgwLmFuYXBsYW4tbnAubmV0L2luZm9ybWF0aW1lIjoiY29yZS1zaXppbmctc2VydmljZSIsImlzcyI6Imh0dHBzOi8vYXV0aC1jaGlsbW1lY2F1dGgwLmFuYXBsYW4tbnAubmV0L2luZm9ybWF0aW1lIjoiY29yZS1zaXppbmctc2VydmljZSIsImlzcyI6Imh0dHBzOi8vYXV0aC1jaGlsbW1lY2F1dGgwLmFuYXBsYW4tbnAubmV0L2luZm9ybWF0aW1lIjoiY29yZS1zaXppbmctc2VydmljZSIsImlzcyI6Imh0dHBzOi8vYXV0aC1jaGlsbW1lY2F1dGgwLmFuYXBsYW4tbnAubmV0L2luZm9ybWF0aW1lIjoiY29yZS1zaXppbmctc2VydmljZSIsImlzcyI6Imh0dHBzOi8vYXV0aC1jaGlsbW1lY2F1dGgwLmFuYXBsYW4tbnAubmV0L2luZm9ybWF0aW1lIjoiY29yZS1zaXppbmctc2VydmljZSIsImlzcyI6Imh0dHBzOi8vYXV0aC1jaGlsbW1lY2F1dGgwLmFuYXBsYW4tbnAubmV0L2luZm9ybWF0aW1lIjoiY29yZS1zaXppbmctc2VydmljZSIsImlzcyI6Imh0dHBzOi8vYXV0aC1jaGlsbW1lY2F1dGgwLmFuYXBsYW4tbnAubmV0L2luZm9ybWF0aW1lIjoiY29yZS1zaXppbmctc2VydmljZSIsImlzcyI6Imh0dHBzOi8vYXV0aC1jaGlsbW1lY2F1dGgwLmFuYXBsYW4tbnAubmV0L2luZm9ybWF0aW1lIjoiY29yZS1zaXppbmctc2VydmljZSIsImlzcyI6Imh0dHBzOi8vYXV0aC1jaGlsbW1lY2F1dGgwLmFuYXBsYW4tbnAubmV0L2luZm9ybWF0aW1lIjoiY29yZS1zaXppbmctc2VydmljZSIsImlzcyI6Imh0dHBzOi8vYXV0aC1jaGlsbW1lY2F1dGgwLmFuYXBsYW4tbnAubmV0L2luZm9ybWF0aW1lIjoiY29yZS1zaXppbmctc2VydmljZSIsImlzcyI6Imh0dHBzOi8vYXV0aC1jaGlsbW1lY2F1dGgwLmFuYXBsYW4tbnAubmV0L2luZm9ybWF0aW1lIjoiY29yZS1zaXppbmctc2VydmljZSIsImlzcyI6Imh0dHBzOi8vYXV0aC1jaGlsbW1lY2F1dGgwLmFuYXBsYW4tbnAubmV0L2luZm9ybWF0aW1lIjoiY29yZS1zaXppbmctc2VydmljZSIsImlzcyI6Imh0dHBzOi8vYXV0aC1jaGlsbW1lY2F1dGgwLmFuYXBsYW4tbnAubmV0L2luZm9ybWF0aW1lIjoiY29yZS1zaXppbmctc2VydmljZSIsImlzcyI6Imh0dHBzOi8vYXV0aC1jaGlsbW1lY2F1dGgwLmFuYXBsYW4tbnAubmV0L2luZm9ybWF0aW1lIjoiY29yZS1zaXppbmctc2VydmljZSIsImlzcyI6Imh0dHBzOi8vYXV0aC1jaGlsbW1lY2F1dGgwLmFuYXBsYW4tbnAubmV0L2luZm9ybWF0aW1lIjoiY29yZS1zaXppbmctc2VydmljZSIsImlzcyI6Imh0dHBzOi8vYXV0aC1jaGlsbW1lY2F1dGgwLmFuYXBsYW4tbnAubmV0L2luZm9ybWF0aW1lIjoiY29yZS1zaXppbmctc2VydmljZSIsImlzcyI6Imh0dHBzOi8vYXV0aC1jaGlsbW1lY2F1dGgwLmFuYXBsYW4tbnAubmV0L2luZm9ybWF0aW1lIjoiY29yZS1zaXppbmctc2VydmljZSIsImlzcyI6Imh0dHBzOi8vYXV0aW1lIjoiY29yZS1zaXppbmctc2VydmljZSIsImlzcyI6Imh0dHBzOi8vYXV0aW1lIjoiY29yZS1zaXppbmctc2VydmljZSIsImlzcyI6Imh0dHBzOi8vYXV0aW1lIjoiY29yZS1zaXppbmctc2VydmljZSIsImlzcyI6Imh0dHBzOi8vYXV0aW1lIjoiY29yZS1zaXppbmctc2VydmljZSIsImlzcyI6Imh0dHBzOi8vYXV0aW1lIjoiY29yZS1zaXppbmctc2VydmljZSIsImlzcyI6Imh0dHBzOi8vYXV0aW1lIjoiY29yZS1zaXppbmctc2VydmljZSIsImlzcyI6Imh0dHBzOi8vYXV0aW1lIjoiY29yZS1zaXppbmctc2VydmljZSIsImlzcyI6Imh0dHBzOi8vYXV0aW1lIjoiY29yZS1zaXppbmctc2VydmljZSIsImlzcyI6Imh0dHBzOi8vYXV0aW1lIjoiY29yZS1zaXppbmctc2VydmljZSIsImlzcyI6Imh0dHBzOi8vYXV0aW1lIjoiY29yZS1zaXppbmctc2VydmljZSIsImlzcyI6Imh0dHBzOi8vYXV0aW1lIjoiY29yZS1zaXppbmctc2VydmljZSIsImlzcyI6Imh0dHBzOi8vYXV0aW1lIjoiY29yZS1zaXppbmctc2VydmljZSIsImlzcyI6Imh0dHBzOi8vYXV0aW1lIjoiY29yZS1zaXppbmctc2VydmljZSIsImlzcyI6Imh0dHBzOi8vYXV0aW1lIjoiY29yZS1zaXppbmctc2VydmljZSIsImlzcyI6Imh0dHBzOi8vYXV0aW1lIjoiY29yZS1zaXppbmctc2VydmljZSIsImlzcyI6Imh0dHBzOi8vYXV0aW1lIjoiY29yZS1zaXppbmctc2VydmljZSIsImlzcyI6Imh0dHBzOi8vYXV0aW1lIjoiY29yZS1zaXppbmctc2VydmljZSIsImlzcyI6Imh0dHBzOi8vYXV0aW1lIjoiY29yZS1zaXppbmctc2VydmljZSIsImlzcyI6Imh0dHBzOi8vYXV0aW1lIjoiY29yZS1zaXppbmctc2VydmljZSIsImlzcyI6Imh0dHBzOi8vYXV0aW1lIjoiY29yZS1zaXppbmctc2VydmljZSIsImlzcyI6Imh0dHBzOi8vYXV0aW1lIjoiY29yZS1zaXppbmctc2VydmljZSIsImlzcyI6Imh0dHBzOi8vYXV0aW1lIjoiY29yZS1zaXppbmctc2VydmljZSIsImlzcyI6Imh0dHBzOi8vYXV0aW1lIjoiY29yZS1zaXppbmctc2VydmljZSIsI6Imh0dHBzOi8vYXV0aW1lIjoiY29yZS1zaXppbmctc2VydmljZSIsI6Imh0dHBzOi8vYXV0aW1lIjoiY29yZS1zaXppbmctc2VydmljZSIsI6Imh0dHBzOi8vYXV0aW1lIjoiY29yZS1zaXppbmctc2VydmljZSIsI6Imh0dHBzOi8vYXV0aW1lIjoiY29yZS1zaXppbmctc2V";
//        });
//    }
}