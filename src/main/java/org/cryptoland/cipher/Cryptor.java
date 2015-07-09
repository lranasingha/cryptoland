package org.cryptoland.cipher;

/**
 * Created by laksithar on 09/07/2015.
 */
public interface Cryptor<PLAIN, ENCRYPTED> {
    ENCRYPTED encrypt(PLAIN input);

    PLAIN decrypt(ENCRYPTED encrypted);
}
