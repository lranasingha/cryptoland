package org.cryptoland.cipher.cryptos;

import org.cryptoland.cipher.Cryptor;

import javax.crypto.Cipher;
import java.security.GeneralSecurityException;
import java.security.KeyPair;

public class RsaCryptor implements Cryptor<String, byte[]> {
    private static final String DEFAULT_TRANSFORMATION_STRATEGY = "RSA/ECB/PKCS1Padding";
    private final KeyPair keyPair;

    public RsaCryptor(KeyPair keyPair) {
        this.keyPair = keyPair;
    }

    public byte[] encrypt(String input) {
        try {
            Cipher cipher = Cipher.getInstance(DEFAULT_TRANSFORMATION_STRATEGY);
            cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());
            return cipher.doFinal(input.getBytes());
        } catch (GeneralSecurityException ex) {
            throw new RuntimeException("failed to encrypt the content", ex);
        }
    }

    public String decrypt(byte[] bytes) {
        try {
            Cipher cipher = Cipher.getInstance(DEFAULT_TRANSFORMATION_STRATEGY);
            cipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
            return new String(cipher.doFinal(bytes));
        } catch (GeneralSecurityException ex) {
            throw new RuntimeException("failed to decrypt the content", ex);
        }
    }
}
