package org.cryptoland.cipher.cryptos;

import org.cryptoland.cipher.keys.RsaKeyPairGenerator;
import org.junit.Before;
import org.junit.Test;

import java.security.KeyPair;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;

public class RsaCryptorTest {

    private KeyPair keyPair;

    @Before
    public void setUp() throws Exception {
        RsaKeyPairGenerator keyPairGenerator = new RsaKeyPairGenerator();
        keyPair = keyPairGenerator.generate();
    }

    @Test
    public void encryptsPlainText() throws Exception {
        String somePlainText = "Hello Rsa..!";
        RsaCryptor cryptor = new RsaCryptor(keyPair);
        byte[] encrypted = cryptor.encrypt(somePlainText);

        assertThat(cryptor.decrypt(encrypted), is(somePlainText));
    }
}