package org.cryptoland.cipher.keys;

import org.cryptoland.cipher.KeyGen;

import java.security.*;
import java.security.spec.ECGenParameterSpec;

import static org.cryptoland.cipher.KeyGen.Algorithm.EllipticCurveIES;

public class SunEllipticCurveIESKeyGenerator implements KeyGen {
    private static final String DEFAULT_CURVE_NAME = "secp192r1";
    private final Provider securityProvider;
    private String curveName = DEFAULT_CURVE_NAME;

    public SunEllipticCurveIESKeyGenerator(final Provider securityProvider) {
        this.securityProvider = securityProvider;
        Security.addProvider(securityProvider);
    }

    public KeyPair generate() {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(EllipticCurveIES.algorithmName(), securityProvider);
            ECGenParameterSpec curveNameParamSpec = new ECGenParameterSpec(curveName);
            keyPairGenerator.initialize(curveNameParamSpec, new SecureRandom());
            return keyPairGenerator.generateKeyPair();
        } catch (GeneralSecurityException e) {
            throw new RuntimeException("Unable to generate Elliptic curve IES key pair", e);
        }
    }

    public SunEllipticCurveIESKeyGenerator withCurveName(final String curveName) {
        this.curveName = curveName;
        return this;
    }
}
