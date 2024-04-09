package ru.orobtsovv.gatewayreactiveservice.client;

import ru.orobtsovv.gatewayreactiveservice.dto.RsaPublicKeyResponse;
import ru.orobtsovv.gatewayreactiveservice.exception.CertsPublicKeyException;
import lombok.RequiredArgsConstructor;
import lombok.Setter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;

@Service
@RequiredArgsConstructor
@Setter
public class AuthClient {
    private final WebClient webClient;

    @Value("${services.certs-endpoint}")
    private String certsURI;

    public Mono<RSAPublicKey> getPublicSignatureKey() {
        return webClient.get()
                .uri(certsURI)
                .retrieve()
                .bodyToMono(RsaPublicKeyResponse.class)
                .map(this::convertToRSAPublicKey)
                .cache();
    }

    private RSAPublicKey convertToRSAPublicKey(RsaPublicKeyResponse response) {
        try {
            BigInteger modulus = new BigInteger(Base64.getUrlDecoder().decode(response.getN()));
            BigInteger exponent = new BigInteger(Base64.getUrlDecoder().decode(response.getE()));
            RSAPublicKeySpec rsaPublicKeySpec = new RSAPublicKeySpec(modulus, exponent);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            return (RSAPublicKey) keyFactory.generatePublic(rsaPublicKeySpec);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            e.printStackTrace();
            throw new CertsPublicKeyException(e);
        }
    }
}
