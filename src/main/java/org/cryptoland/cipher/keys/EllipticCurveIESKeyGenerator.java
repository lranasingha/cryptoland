package org.cryptoland.cipher.keys;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.cryptoland.cipher.KeyGen;

import java.security.*;
import java.security.spec.ECGenParameterSpec;

import static org.cryptoland.cipher.KeyGen.Algorithm.EllipticCurveIES;

public class EllipticCurveIESKeyGenerator implements KeyGen {
    private static final String DEFAULT_CURVE_NAME = "prime192v1";
    private String curveName = DEFAULT_CURVE_NAME;

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public KeyPair generate() {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(EllipticCurveIES.algorithmName(), "BC");
            ECGenParameterSpec curveNameParamSpec = new ECGenParameterSpec(curveName);
            keyPairGenerator.initialize(curveNameParamSpec, new SecureRandom());
            return keyPairGenerator.generateKeyPair();
        } catch (GeneralSecurityException e) {
            throw new RuntimeException("Unable to generate Elliptic curve IES key pair", e);
        }
    }

    public EllipticCurveIESKeyGenerator withCurveName(final String curveName) {
        this.curveName = curveName;
        return this;
    }
}
