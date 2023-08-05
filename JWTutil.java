// Importaciones necesarias para trabajar con JWT
package com.bnozzi.login.auth;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;
import java.security.Key;
import java.util.Date;

@Component
public class JWTutil {
    // Valores de configuración para JWT
    @Value("${security.jwt.secret}")
    private String key; // Clave secreta utilizada para firmar el token

    @Value("${security.jwt.issuer}")
    private String issuer; // Emisor del token

    @Value("${security.jwt.ttlMillis}")
    private long ttlMillis; // Tiempo de vida del token (expiración)

    private final Logger log = LoggerFactory.getLogger(JWTutil.class);

    /**
     * Crea un nuevo token JWT.
     *
     * @param id      El ID del token.
     * @param subject El sujeto del token (generalmente el username del usuario).
     * @return El token JWT creado.
     */
    public String create(String id, String subject) {
        // Algoritmo de firma utilizado para firmar el token JWT
        SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.HS256;

        long nowMillis = System.currentTimeMillis();
        Date now = new Date(nowMillis);

        // Se firma el JWT con la clave secreta proporcionada
        byte[] apiKeySecretBytes = DatatypeConverter.parseBase64Binary(key);
        Key signingKey = new SecretKeySpec(apiKeySecretBytes, signatureAlgorithm.getJcaName());

        // Se configuran los Claims (contenido del token JWT)
        JwtBuilder builder = Jwts.builder().setId(id).setIssuedAt(now).setSubject(subject).setIssuer(issuer)
                .signWith(signatureAlgorithm, signingKey);

        if (ttlMillis >= 0) {
            // Si se ha configurado un tiempo de vida, se agrega la fecha de expiración al token
            long expMillis = nowMillis + ttlMillis;
            Date exp = new Date(expMillis);
            builder.setExpiration(exp);
        }

        // Se construye el JWT y se serializa a una cadena compacta y segura para URL
        return builder.compact();
    }

    /**
     * Método para validar y leer el contenido del JWT y obtener el sujeto (username).
     *
     * @param jwt El token JWT a validar y leer.
     * @return El sujeto (username) extraído del token.
     */
    public String getValue(String jwt) {
        // Esta línea lanzará una excepción si el JWT no está firmado correctamente (como se espera)
        Claims claims = Jwts.parser().setSigningKey(DatatypeConverter.parseBase64Binary(key))
                .parseClaimsJws(jwt).getBody();

        // Se obtiene el sujeto (username) del token JWT
        return claims.getSubject();
    }

    /**
     * Método para validar y leer el contenido del JWT y obtener el ID del token.
     *
     * @param jwt El token JWT a validar y leer.
     * @return El ID del token extraído del JWT.
     */
    public String getKey(String jwt) {
        // Esta línea lanzará una excepción si el JWT no está firmado correctamente (como se espera)
        Claims claims = Jwts.parser().setSigningKey(DatatypeConverter.parseBase64Binary(key))
                .parseClaimsJws(jwt).getBody();

        // Se obtiene el ID del token del token JWT
        return claims.getId();
    }
}

