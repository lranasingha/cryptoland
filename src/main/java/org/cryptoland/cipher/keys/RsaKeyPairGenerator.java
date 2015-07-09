package org.cryptoland.cipher.keys;

import org.cryptoland.cipher.KeyGen;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import static org.cryptoland.cipher.KeyGen.Algorithm.Rsa;

public class RsaKeyPairGenerator implements KeyGen {
    private static final int DEFAULT_KEY_SIZE = 1024;
    private int keySize = DEFAULT_KEY_SIZE;

    public KeyPair generate() {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(Rsa.algorithmName());
            keyPairGenerator.initialize(keySize, new SecureRandom());
            return keyPairGenerator.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Unable to generate key pair using Rsa", e);
        }
    }

    public RsaKeyPairGenerator with(int keySize) {
        this.keySize = keySize;
        return this;
    }
}
