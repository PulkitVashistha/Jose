package com.jose.encryption.core.util;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.SignedJWT;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

public class JoseUtil {
    //===================================================================================================================================================================================
    //NOTE
    //rsaPublicKey  is the recipient Public Key we fetch from KeyStore which we use for encrypting the payload and creating the JWE object.
    //rsaPrivateKey is our private key that we sign the JWT object with and the receiver uses our public key to check the signing of the message to ensure the authenticity of the token.
    //===================================================================================================================================================================================

    private JoseUtil(){
        //Private constructor for Util class
    }

    //In the method below, we’ll be decrypting the message using our private key (to verify the Token Signature) and sender’s Public key (to decrypt the payload).
    //response is the received response from the sender below.
    /**
     * Decrypts String with Jose Algorithm using sender's public key and receiver's private key
     * @param rsaPublicKey
     * @param rsaPrivateKey
     * @param response
     * @return
     * @throws Exception
     */
    public static String decryptResponseWithJose(RSAPublicKey rsaPublicKey, RSAPrivateKey rsaPrivateKey, String response) throws Exception {
        JWEObject jweObject;
        try{
            SignedJWT signedJWT = SignedJWT.parse(response);
            signedJWT.verify(new RSASSAVerifier(rsaPublicKey));
            jweObject = JWEObject.parse(signedJWT.getPayload().toString());
            jweObject.decrypt(new RSADecrypter(rsaPrivateKey));
        } catch (Exception e){
            throw new Exception("|||||||ERROR in decrypting string with Jose |||||||"+e.getMessage());
        }
        return jweObject.getPayload().toString();
    }

    /**
     * Encrypts String using Jose Algorithm using sender's private key and receiver's public key and other relevant information
     * @param rsaPublicKey
     * @param rsaPrivateKey
     * @param payload
     * @param jweThumbprint
     * @param jwsThumbprint
     * @param clientId
     * @return
     * @throws Exception
     */
    public static String encryptRequestWithJose(RSAPublicKey rsaPublicKey, RSAPrivateKey rsaPrivateKey,String payload, String jweThumbprint, String jwsThumbprint, String clientId) throws  Exception {
        JWSObject jwsObject;
        try {
            // Creating JWE object with request as payload
            JWEObject jweObject = new JWEObject(
                    new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM)
                            .x509CertSHA256Thumbprint(Base64URL.from(jweThumbprint))
                            .customParam("clientid", clientId)
                            .build(),
                    new Payload(payload));
            // Encrypt JWE Object with the receiver's public key
            jweObject.encrypt(new RSAEncrypter(rsaPublicKey));
            // Serialise to JWE compact form
            String jweString = jweObject.serialize();
            // Creating JWS Object with JWE as payload
            jwsObject = new JWSObject(
                    new JWSHeader.Builder(JWSAlgorithm.PS256)
                            .customParam("clientid", clientId)
                            .x509CertSHA256Thumbprint(Base64URL.from(jwsThumbprint))
                            .contentType("JWT") // required to indicate nested JWT
                            .build(),
                    new Payload(jweString));
            // Signing the JWS Object with sender's private key
            jwsObject.sign(new RSASSASigner(rsaPrivateKey));
        } catch (Exception e){
            throw new Exception("|||||||ERROR in encrypting string with Jose|||||||" + e.getMessage());
        }

        return jwsObject.serialize();
    }
}
