package org.cryptoland.cipher.cryptos;

import org.cryptoland.cipher.Cryptor;

import javax.crypto.Cipher;
import java.security.GeneralSecurityException;
import java.security.KeyPair;

public class EllipticCurveIesCryptor implements Cryptor<String, byte[]> {
    private final KeyPair keyPair;

    public EllipticCurveIesCryptor(KeyPair keyPair) {
        this.keyPair = keyPair;
    }

    public byte[] encrypt(String input) {
        try {
            Cipher cipher = Cipher.getInstance("ECIES");
            cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());
            return cipher.doFinal(input.getBytes());
        } catch (GeneralSecurityException e) {
            throw new RuntimeException("Failed to encrypt using ECIES cipher", e);
        }
    }

    public String decrypt(byte[] bytes) {
        try {
            Cipher cipher = Cipher.getInstance("ECIES");
            cipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
            return new String(cipher.doFinal(bytes));
        } catch (GeneralSecurityException e) {
            throw new RuntimeException("Failed to decrypt using ECIES cipher", e);
        }
    }
}
