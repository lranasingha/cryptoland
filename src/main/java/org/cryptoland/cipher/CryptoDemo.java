package org.cryptoland.cipher;

import org.cryptoland.cipher.cryptos.EllipticCurveIesCryptor;
import org.cryptoland.cipher.cryptos.RsaCryptor;
import org.cryptoland.cipher.keys.EllipticCurveIESKeyGenerator;
import org.cryptoland.cipher.keys.RsaKeyPairGenerator;

import java.security.KeyPair;

public class CryptoDemo {
    public static void main(String[] args) {
        //RSA 1024b encryption
        String content = "Hello There..!";
        System.out.println("-- RSA Encryption on --" + content);
        RsaKeyPairGenerator rsaGenerator = new RsaKeyPairGenerator();
        KeyPair rsaKeyPair = rsaGenerator.generate();

        RsaCryptor rsaCryptor = new RsaCryptor(rsaKeyPair);
        byte[] encrypted = rsaCryptor.encrypt(content);
        System.out.println("Encrypted --> " + new String(encrypted));
        String decrypted = rsaCryptor.decrypt(encrypted);
        System.out.println("Decrypted --> " + decrypted + "\n");

        //EllipticCurve IES
        System.out.println("-- ECIES Encryption on -- " + content);
        EllipticCurveIESKeyGenerator ecdsaKeyGenerator = new EllipticCurveIESKeyGenerator();
        KeyPair ecdsaKeyPair = ecdsaKeyGenerator.generate();
        EllipticCurveIesCryptor ecdsaCryptor = new EllipticCurveIesCryptor(ecdsaKeyPair);
        encrypted = ecdsaCryptor.encrypt(content);
        System.out.println("Encrypted --> " + new String(encrypted));
        decrypted = ecdsaCryptor.decrypt(encrypted);
        System.out.println("Decrypted --> " + decrypted);


    }
}
