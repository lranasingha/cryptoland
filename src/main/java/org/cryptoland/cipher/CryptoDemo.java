package org.cryptoland.cipher;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.cryptoland.cipher.cryptos.EllipticCurveIesCryptor;
import org.cryptoland.cipher.cryptos.RsaCryptor;
import org.cryptoland.cipher.keys.BcEllipticCurveIESKeyGenerator;
import org.cryptoland.cipher.keys.RsaKeyPairGenerator;
import sun.security.ec.SunEC;

import java.security.KeyPair;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.function.Consumer;
import java.util.function.Supplier;
import java.util.stream.IntStream;

import static java.lang.String.format;
import static java.lang.System.out;

public class CryptoDemo {
    public static void main(String[] args) {
        //RSA 1024b encryption
        String content = "Hello There..!";
        int times = 1000;

        RsaKeyPairGenerator rsaGenerator = new RsaKeyPairGenerator();
        KeyPair rsaKeyPair = rsaGenerator.generate();
        RsaCryptor rsaCryptor = new RsaCryptor(rsaKeyPair);
        out.println("-- RSA 1024b Encryption on --" + content);
        Duration rsaExecutionDuration = timedExecutionOf(s -> rsaCryptor.decrypt(rsaCryptor.encrypt(s)), content, times).get();
        printDuration("Rsa", times, rsaExecutionDuration);

        //EllipticCurve BouncyCastle IES
        BcEllipticCurveIESKeyGenerator bcEcdsaKeyGenerator = new BcEllipticCurveIESKeyGenerator(new BouncyCastleProvider()).withCurveName("secp192k1");
        KeyPair bcEcdsaKeyPair = bcEcdsaKeyGenerator.generate();
        EllipticCurveIesCryptor bcEcdsaCryptor = new EllipticCurveIesCryptor(bcEcdsaKeyPair);
        out.println("-- EC 160b Encryption using Bouncy Castle Provider on -- " + content);
        Duration eccBcExecutionDuration = timedExecutionOf(s -> bcEcdsaCryptor.decrypt(bcEcdsaCryptor.encrypt(s)), content, times).get();
        printDuration("EC BC", times, eccBcExecutionDuration);

        //EllipticCurve IES SunEC
        out.println("-- EC 160b Encryption using Sun EC Provider on -- " + content);
        BcEllipticCurveIESKeyGenerator sunEcdsaKeyGenerator = new BcEllipticCurveIESKeyGenerator(new SunEC()).withCurveName("secp192k1");
        KeyPair sunEcdsaKeyPair = sunEcdsaKeyGenerator.generate();
        EllipticCurveIesCryptor sunEcdsaCryptor = new EllipticCurveIesCryptor(sunEcdsaKeyPair);
        Duration eccSunExecutionDuration = timedExecutionOf(s -> sunEcdsaCryptor.decrypt(sunEcdsaCryptor.encrypt(s)), content, times).get();
        printDuration("EC SUN", times, eccSunExecutionDuration);
    }

    private static void printDuration(final String algorithm, final int rounds, final Duration elapsed) {
        out.println(format("Time taken to do %d rounds of encryption/decryption using %s algorithm = %dms", rounds, algorithm, elapsed.toMillis()));
    }

    private static Supplier<Duration> timedExecutionOf(Consumer<String> task, final String input, final int times) {
        Instant before = Clock.systemUTC().instant();

        IntStream.range(0, times).forEach(i -> task.accept(input));

        Instant after = Clock.systemUTC().instant();
        return () -> Duration.between(before, after);
    }
}
