package org.example;

import com.auth0.jwk.JwkException;
import com.auth0.jwk.JwkProvider;
import com.auth0.jwk.JwkProviderBuilder;
import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.RSAKeyProvider;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.TimeUnit;

public final class JWTVerifierExample {
    private JWTVerifierExample() {
    }

    public static void main(final String[] args) {
        try {
            // RSA256 Key Provider
            final Algorithm algorithm = Algorithm.RSA256(buildKeyProvider());
            
            final String expectedIssuer = "https://XXXX/";
            final String expectedAudience = "https://XXXX";
            final Set<String> requiredScopes = new HashSet<>(Arrays.asList("request:size")); // Required scopes

            final JWTVerifier verifier = JWT.require(algorithm)
                .withIssuer(expectedIssuer)
                .withAudience(expectedAudience)
                .build();

            // Decode and verify the JWT
            final String token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImdpaXF3ZTB6OVNSblQwbVVLejVxRiJ9.eyJhcHBOYW1lIjoiY29yZS1zaXppbmctc2VydmljZSIsImlzcyI6Imh0dHBzOi8vYXV0aC1jaGltZXJhLmF1dGgwLmFuYXBsYW4tbnAubmV0LyIsInN1YiI6ImsxWW94alpKYlhqQXRaZ0JzT1U3MENhVEtBVkRacVBrQGNsaWVudHMiLCJhdWQiOiJodHRwczovL2NvcmUtc2l6aW5nLmFuYXBsYW4uY29tIiwiaWF0IjoxNzMyMjY1NzAzLCJleHAiOjE3MzIyNzY1MDMsInNjb3BlIjoicmVxdWVzdDpzaXplIiwiZ3R5IjoiY2xpZW50LWNyZWRlbnRpYWxzIiwiYXpwIjoiazFZb3hqWkpiWGpBdFpnQnNPVTcwQ2FUS0FWRFpxUGsifQ.YRu-AcKYXAjb6LWuv1RxJiIJg5IYaY9z23NMkPZX5Mjf1lswK1pAxv5uvxuM0dV8enJoaghoLuAxGBKRNjXy1tnnJWA1Tj3NElC8mvuWofLoyzDrNbGdp4MKCmSgck2GUjY5RBmqNfUmxxllnCEdl7Kba3-uj7DcZKYT6DAo_gVf5ISs-31g18A654_sMSccoOoxxCNV_3Rp41uXNhsFCx6eW3YEJKwV9Adz7ThDUkXr4ZgUT_8OQYc1D3qahBBlRsrf5OA5_SsRRv7DlxJ9UcUhKf071XcHapQKq6iEzHjYC2u2t0c5E4AcwIiLwDWBR_mD2ZiS9fwPC4CcKOpnEA";
            final DecodedJWT jwt = verifier.verify(token);
            // Validate the "scope" claim
            final Claim scopeClaim = jwt.getClaim("scope");
            if (!validateScopeClaim(scopeClaim, requiredScopes)) {
                throw new JWTVerificationException("Invalid scope claim");
            }
            System.out.println("JWT is valid and scopes are correct!");
        } catch (final JWTVerificationException ex) {
            System.out.println("Invalid JWT: " + ex.getMessage());
        }
    }

    // Validator for the "scope" claim
    private static boolean validateScopeClaim(final Claim claim, final Set<String> requiredScopes) {
        if (claim == null || claim.isNull()) {
            return false;
        }
        // Handle scope as space-separated string
        if (claim.asString() != null) {
            final Set<String> scopes = new HashSet<>(Arrays.asList(claim.asString().split(" ")));
            return scopes.containsAll(requiredScopes);
        }
         return false;
    }

    // Mock KeyProvider - replace this with your implementation
    private static RSAKeyProvider buildKeyProvider() {
        return new RSAKeyProvider() {
            @Override
            public RSAPublicKey getPublicKeyById(final String kid) {
                try {
                    return (RSAPublicKey) jwkProvider().get(kid).getPublicKey();
                } catch (final JwkException e) {
                    return null;
                }
            }

            @Override
            public RSAPrivateKey getPrivateKey() {
                return null;
            }

            @Override
            public String getPrivateKeyId() {
                return null;
            }
        };
    }
    public static JwkProvider jwkProvider() {
        return new JwkProviderBuilder("https://google.com/")
                .cached(10, 24, TimeUnit.HOURS)
                .rateLimited(10, 1, TimeUnit.MINUTES)
                .build();
    }
}
