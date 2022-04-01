package com.jose.encryption.core.util;

import com.adobe.granite.keystore.KeyStoreService;
import com.jose.encryption.core.service.ResourceResolverService;
import org.apache.sling.api.resource.ResourceResolver;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.*;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Objects;

public class KeysUtil {

    private static final Logger logger = LoggerFactory.getLogger(KeysUtil.class);

    private KeysUtil() {
        //Private Constructor for Util class
    }

    //========================================================================================
    //NOTE
    //Below method is for fetching public key from TrustStore where we uploaded the public certificate.
    //As the trust store is public, password is not needed.
    //We just need to send the alias (randomly generated at the time of certificate upload)
    //And keystore service reference along with the resourceResolver.
    //========================================================================================
    /**
     * returns public key from keystore using trustStoreAlias
     * @param resourceResolverService
     * @param keyStoreService
     * @param trustStoreAlias
     * @return
     */
    public static RSAPublicKey fetchPublicKey(ResourceResolverService resourceResolverService, KeyStoreService keyStoreService, String trustStoreAlias){
        ResourceResolver resourceResolver = resourceResolverService.getReadSystemResourceResolver();
        KeyStore trustStore  = keyStoreService.getTrustStore(resourceResolver);
        PublicKey publicKey = null;
        if (trustStore != null) {
            X509Certificate crt = null;
            try {
                crt = (X509Certificate) trustStore.getCertificate(trustStoreAlias);
            } catch (KeyStoreException e) {
                logger.error("Error in Fetching Public Key",e);
            }
            publicKey = Objects.nonNull(crt) ? crt.getPublicKey() : null;
        }
        return  (RSAPublicKey) publicKey;
    }

    //========================================================================================================================
    //NOTE
    //Below method is for fetching (your) private key from keystore where we uploaded our keystore file comprising our key pair.
    //As the keystore is mapped to a system user, we need to send a resource resolver of that system user which has read access, which I am fetching via resourceResolverService.getReadSystemResourceResolver();  In the below function.
    //Also we need to send the KeyStoreService reference, along with the keystore alias(alias that is mapped to the certificate and can be seen in the first column of the certificate list) and keystore password(that we set @ the time of setting up keystore)
    //========================================================================================================================
    /**
     * returns Private Key from KeyStore using alias and password
     * @param resourceResolverService
     * @param keyStoreService
     * @param keyStoreAlis
     * @param keyStorePwd
     * @return
     */
    public static RSAPrivateKey fetchPrivateKey(ResourceResolverService resourceResolverService, KeyStoreService keyStoreService, String keyStoreAlis, String keyStorePwd) {
        ResourceResolver resourceResolver = resourceResolverService.getReadSystemResourceResolver();
        KeyStore keyStore = keyStoreService.getKeyStore(resourceResolver);
        RSAPrivateKey privateKey = null;
        try {
            privateKey = (RSAPrivateKey)keyStore.getKey(keyStoreAlis, keyStorePwd.toCharArray());
        } catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException e) {
            logger.error("Error in Fetching Private Key",e);
        }
        return privateKey;
    }
}
