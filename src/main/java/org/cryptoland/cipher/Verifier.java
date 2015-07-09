package org.cryptoland.cipher;

/**
 * Created by laksithar on 09/07/2015.
 */
public interface Verifier<INPUT, SIGNATURE> {
    boolean verify(INPUT input, SIGNATURE signature);
}
