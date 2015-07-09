package org.cryptoland.cipher.cryptos;

import org.cryptoland.cipher.keys.EllipticCurveIESKeyGenerator;
import org.junit.Before;
import org.junit.Test;

import java.security.KeyPair;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;

public class EllipticCurveIesCryptorTest {

    private KeyPair keyPair;

    @Before
    public void setUp() throws Exception {
        EllipticCurveIESKeyGenerator keyPairGenerator = new EllipticCurveIESKeyGenerator();
        keyPair = keyPairGenerator.generate();
    }

    @Test
    public void encryptsPlainText() throws Exception {
        String somePlainText = "Welcome to Elliptic Curve Encryption..!";
        EllipticCurveIesCryptor cryptor = new EllipticCurveIesCryptor(keyPair);
        byte[] encrypted = cryptor.encrypt(somePlainText);

        assertThat(cryptor.decrypt(encrypted), is(somePlainText));
    }
}