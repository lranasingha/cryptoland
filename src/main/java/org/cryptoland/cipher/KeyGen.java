package org.cryptoland.cipher;

import java.security.KeyPair;

public interface KeyGen {
    enum Algorithm {
        Rsa("RSA"),
        EllipticCurveIES("EC");

        private String algorithmName;

        Algorithm(String algorithmName) {

            this.algorithmName = algorithmName;
        }

        public String algorithmName() {
            return algorithmName;
        }
    }

    KeyPair generate();
}
