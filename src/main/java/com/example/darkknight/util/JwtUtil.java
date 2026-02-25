package com.example.darkknight.util;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Map;

/**
 * Utility for validating tenant-specific JWT tokens issued by an external IdP
 * (e.g. MiniOrange JWT SSO).
 *
 * <p>
 * Signing algorithms supported:
 * <ul>
 * <li><b>HS256</b> – HMAC-SHA-256 (default; most IdPs use this)</li>
 * <li><b>HS384</b> – HMAC-SHA-384</li>
 * <li><b>HS512</b> – HMAC-SHA-512</li>
 * </ul>
 *
 * <p>
 * The algorithm is stored per-tenant in {@code TenantSsoConfig.jwtAlgorithm}
 * and selected at validation time.
 */
@Component
public class JwtUtil {

    private static final Logger logger = LoggerFactory.getLogger(JwtUtil.class);

    /**
     * Validate an incoming JWT token using the tenant's configured signing secret
     * and algorithm.
     *
     * @param token     Raw JWT string (three-part base64url-encoded)
     * @param secretKey The plain-text client secret stored in TenantSsoConfig
     * @param algorithm Algorithm name: "HS256", "HS384", or "HS512" (default HS256)
     * @return Parsed claims map on success
     * @throws io.jsonwebtoken.JwtException if the token is invalid, expired, or
     *                                      tampered
     */
    public Map<String, Object> validateToken(String token, String secretKey, String algorithm) {
        SignatureAlgorithm sigAlg = resolveAlgorithm(algorithm);
        SecretKey key = buildKey(secretKey, sigAlg);

        logger.debug("Validating JWT with algorithm: {}", sigAlg.getValue());

        Claims claims = Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .getBody();

        logger.debug("JWT validated successfully. Subject: {}", claims.getSubject());
        return claims;
    }

    /**
     * Overload that defaults to HS256 when no algorithm is specified or stored.
     */
    public Map<String, Object> validateToken(String token, String secretKey) {
        return validateToken(token, secretKey, "HS256");
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    /**
     * Resolve a human-readable algorithm name to the JJWT enum value.
     * Falls back to HS256 for null / unknown values.
     */
    public static SignatureAlgorithm resolveAlgorithm(String name) {
        if (name == null || name.isBlank()) {
            return SignatureAlgorithm.HS256;
        }
        switch (name.toUpperCase()) {
            case "HS384":
                return SignatureAlgorithm.HS384;
            case "HS512":
                return SignatureAlgorithm.HS512;
            default:
                return SignatureAlgorithm.HS256;
        }
    }

    /**
     * Build a {@link SecretKey} from a plain-text secret, correctly sized for
     * the chosen HMAC algorithm.
     *
     * <p>
     * JJWT requires the key to be at least as long as the algorithm's minimum
     * bit-length. If the supplied secret is shorter, we pad it with zeros so that
     * we never throw a WeakKeyException — matching the behaviour most IdPs expect.
     */
    private SecretKey buildKey(String secretKey, SignatureAlgorithm alg) {
        byte[] rawBytes = secretKey.getBytes(StandardCharsets.UTF_8);
        int minBytes = alg.getMinKeyLength() / 8; // minKeyLength is in bits

        if (rawBytes.length < minBytes) {
            logger.warn("JWT secret is shorter than recommended for {}. " +
                    "Got {} bytes, need at least {}. Padding with zeros.",
                    alg.getValue(), rawBytes.length, minBytes);
            byte[] padded = new byte[minBytes];
            System.arraycopy(rawBytes, 0, padded, 0, rawBytes.length);
            rawBytes = padded;
        }

        return Keys.hmacShaKeyFor(rawBytes);
    }
}
