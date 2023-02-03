package top.opencodes.sm2.util;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.engines.SM2Engine;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.*;
import org.bouncycastle.jce.spec.ECParameterSpec;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;
import org.bouncycastle.jce.ECNamedCurveTable;
public class Sm2KeyHelp {


    /**
     * 生成随机字符串 [0-9,a-z,A-Z]
     *
     * @param random
     * @param characters
     * @param len
     * @return
     */
    public static String genRandomString(Random random, String characters, int len) {
        char[] text = new char[len];
        for (int i = 0; i < len; i++) {
            text[i] = characters.charAt(random.nextInt(characters.length()));
        }
        return new String(text);
    }


    /**
     * 生成国密密钥对
     *
     * @return
     */
    public static Map<String, byte[]> CMBSM2KeyGen() {
        ECDomainParameters domainParameters = getECDomainParameters();
        ECKeyPairGenerator generator = new ECKeyPairGenerator();
        ECKeyGenerationParameters parameters = new ECKeyGenerationParameters(domainParameters, new SecureRandom());
        generator.init(parameters);
        AsymmetricCipherKeyPair keyPair = generator.generateKeyPair();
        ECPublicKeyParameters publicKeyParameters = (ECPublicKeyParameters) keyPair.getPublic();
        ECPrivateKeyParameters privateKeyParameters = (ECPrivateKeyParameters) keyPair.getPrivate();
        Map<String, byte[]> map = new HashMap<>();
        map.put("publickey", publicKeyParameters.getQ().getEncoded(false));
        map.put("privatekey", format(privateKeyParameters.getD().toByteArray()));
        return map;
    }
    private static ECDomainParameters getECDomainParameters() {
        ECParameterSpec spec = ECNamedCurveTable.getParameterSpec("sm2p256v1");
        return new ECDomainParameters(spec.getCurve(), spec.getG(), spec.getN(), spec.getH(), spec.getSeed());
    }
    private static byte[] format(byte[] value) {
        if (value.length == 32) {
            return value;
        }
        byte bytes[] = new byte[32];
        if (value.length > 32) {
            System.arraycopy(value, value.length - 32, bytes, 0, 32);
        } else {
            System.arraycopy(value, 0, bytes, 32 - value.length, value.length);
        }
        return bytes;
    }

    // sm2 加密
    public static byte[] CMBSM2Encrypt(byte pubkey[], byte msg[]) throws Exception {
        ECPublicKeyParameters publicKey = null;
        publicKey = DCCryptor.encodePublicKey(pubkey);
        SM2Engine engine = new SM2Engine();
        engine.init(true, new ParametersWithRandom(publicKey, new SecureRandom()));

        byte cipherText[] = engine.processBlock(msg, 0, msg.length);
        return C1C2C3ToC1C3C2(cipherText);
    }

    // sm2 解密
    public static byte[] CMBSM2Decrypt(byte privkey[], byte msg[]) throws Exception {
        msg = C1C3C2ToC1C2C3(msg);
        ECPrivateKeyParameters privateKey = null;
        privateKey = encodePrivateKey(privkey);
        SM2Engine engine = new SM2Engine();
        engine.init(false, privateKey);
        return engine.processBlock(msg, 0, msg.length);
    }

    private static ECPrivateKeyParameters encodePrivateKey(byte value[]) {
        BigInteger d = new BigInteger(1, value);
        return new ECPrivateKeyParameters(d, getECDomainParameters());
    }

    private static byte[] C1C2C3ToC1C3C2(byte cipherText[]) throws Exception {
        if (cipherText == null || cipherText.length < 97) {
            throw new Exception("E10406");
        } else {
            byte bytes[] = new byte[cipherText.length];
            System.arraycopy(cipherText, 0, bytes, 0, 65);
            System.arraycopy(cipherText, cipherText.length - 32, bytes, 65, 32);
            System.arraycopy(cipherText, 65, bytes, 97, cipherText.length - 97);
            return bytes;
        }
    }

    private static byte[] C1C3C2ToC1C2C3(byte cipherText[]) throws Exception {
        if (cipherText == null || cipherText.length < 97) {
            throw new Exception("E10406");
        } else {
            byte bytes[] = new byte[cipherText.length];
            System.arraycopy(cipherText, 0, bytes, 0, 65);
            System.arraycopy(cipherText, 97, bytes, 65, cipherText.length - 97);
            System.arraycopy(cipherText, 65, bytes, cipherText.length - 32, 32);
            return bytes;
        }
    }


}
