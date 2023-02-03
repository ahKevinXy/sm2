package top.opencodes.sm2.util;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.security.Security;
import java.util.Enumeration;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithID;
import org.bouncycastle.crypto.signers.SM2Signer;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECPoint;

/**
 * 示例代码，仅供参考
 */
public class DCCryptor {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static byte[] CMBSM4EncryptWithCBC(byte key[], byte iv[], byte input[]) throws Exception {
        if (key == null || iv == null || input == null) {
            throw new Exception("CMBSM4EncryptWithCBC 非法输入");
        }
        return CMBSM4Crypt(key, iv, input, 1);
    }

    public static byte[] CMBSM4DecryptWithCBC(byte key[], byte iv[], byte input[]) throws Exception {
        if (key == null || iv == null || input == null) {
            throw new Exception("CMBSM4DecryptWithCBC 非法输入");
        }
        return CMBSM4Crypt(key, iv, input, 2);
    }

    public static byte[] CMBSM2SignWithSM3(byte[] id, byte privkey[], byte msg[]) throws Exception {
        if (privkey == null || msg == null) {
            throw new Exception("CMBSM2SignWithSM3 input error");
        }
        ECPrivateKeyParameters privateKey = encodePrivateKey(privkey);
        SM2Signer signer = new SM2Signer();
        ParametersWithID parameters = new ParametersWithID(privateKey, id);
        signer.init(true, parameters);
        signer.update(msg, 0, msg.length);
        return decodeDERSignature(signer.generateSignature());
    }

    public static boolean CMBSM2VerifyWithSM3(byte[] id, byte pubkey[], byte msg[], byte signature[]) throws Exception {

        if (pubkey == null || msg == null || signature == null) {
            throw new Exception("CMBSM2VerifyWithSM3 input error");
        }
        ECPublicKeyParameters publicKey = encodePublicKey(pubkey);
        SM2Signer signer = new SM2Signer();
        ParametersWithID parameters = new ParametersWithID(publicKey, id);
        signer.init(false, parameters);
        signer.update(msg, 0, msg.length);
        return signer.verifySignature(encodeDERSignature(signature));
    }

    private static byte[] CMBSM4Crypt(byte key[], byte iv[], byte input[], int mode) throws Exception {
        SecretKeySpec spec = new SecretKeySpec(key, "SM4");
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
        Cipher cipher = Cipher.getInstance("SM4/CBC/PKCS7Padding", BouncyCastleProvider.PROVIDER_NAME);
        cipher.init(mode, spec, ivParameterSpec);
        return cipher.doFinal(input);
    }

    private static ECPrivateKeyParameters encodePrivateKey(byte[] value) {
        BigInteger d = new BigInteger(1, value);
        ECParameterSpec spec = ECNamedCurveTable.getParameterSpec("sm2p256v1");
        ECDomainParameters ecParameters = new ECDomainParameters(spec.getCurve(), spec.getG(), spec.getN(), spec.getH(), spec.getSeed());
        return new ECPrivateKeyParameters(d, ecParameters);
    }

    public static ECPublicKeyParameters encodePublicKey(byte[] value) {
        byte[] x = new byte[32];
        byte[] y = new byte[32];
        System.arraycopy(value, 1, x, 0, 32);
        System.arraycopy(value, 33, y, 0, 32);
        BigInteger X = new BigInteger(1, x);
        BigInteger Y = new BigInteger(1, y);
        ECParameterSpec spec = ECNamedCurveTable.getParameterSpec("sm2p256v1");
        ECPoint Q = spec.getCurve().createPoint(X, Y);
        ECDomainParameters ecParameters = new ECDomainParameters(spec.getCurve(), spec.getG(), spec.getN(), spec.getH(), spec.getSeed());
        return new ECPublicKeyParameters(Q, ecParameters);
    }

    @SuppressWarnings("unchecked")
    private static byte[] decodeDERSignature(byte[] signature) throws Exception {
        ASN1InputStream stream = new ASN1InputStream(new ByteArrayInputStream(signature));
        ASN1Sequence primitive = (ASN1Sequence) stream.readObject();
        Enumeration<ASN1Integer> enumeration = primitive.getObjects();
        BigInteger R = enumeration.nextElement().getValue();
        BigInteger S = enumeration.nextElement().getValue();
        byte[] bytes = new byte[64];
        byte[] r = format(R.toByteArray());
        byte[] s = format(S.toByteArray());
        System.arraycopy(r, 0, bytes, 0, 32);
        System.arraycopy(s, 0, bytes, 32, 32);
        return bytes;
    }

    private static byte[] encodeDERSignature(byte[] signature) throws Exception {
        byte[] r = new byte[32];
        byte[] s = new byte[32];
        System.arraycopy(signature, 0, r, 0, 32);
        System.arraycopy(signature, 32, s, 0, 32);
        ASN1EncodableVector vector = new ASN1EncodableVector();
        vector.add(new ASN1Integer(new BigInteger(1, r)));
        vector.add(new ASN1Integer(new BigInteger(1, s)));
        return (new DERSequence(vector)).getEncoded();
    }

    private static byte[] format(byte[] value) {
        if (value.length == 32) {
            return value;
        } else {
            byte[] bytes = new byte[32];
            if (value.length > 32) {
                System.arraycopy(value, value.length - 32, bytes, 0, 32);
            } else {
                System.arraycopy(value, 0, bytes, 32 - value.length, value.length);
            }
            return bytes;
        }
    }

}
