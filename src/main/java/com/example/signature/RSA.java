package com.example.signature;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Date;
import javax.crypto.Cipher;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource.PSpecified;

import lombok.extern.slf4j.Slf4j;
//import org.apache.commons.codec.binary.Hex;
import sun.security.x509.AlgorithmId;
import sun.security.x509.CertificateAlgorithmId;
import sun.security.x509.CertificateSerialNumber;
import sun.security.x509.CertificateValidity;
import sun.security.x509.CertificateVersion;
import sun.security.x509.CertificateX509Key;
import sun.security.x509.X500Name;
import sun.security.x509.X509CertImpl;
import sun.security.x509.X509CertInfo;

@Slf4j
public class RSA {
    private static final String default_algorithm = "RSA";
    private static final String default_provider = "BC";
    private static final String default_sign_algorithm = "SHA256withDSA";
    private static final int default_size = 2048;
    private static final int valid_days = 3650;

    public RSA() {
    }

    static X509Certificate generateCertificate(KeyPair pair, String dn, int days, String algorithm) throws GeneralSecurityException, IOException {
        PrivateKey privkey = pair.getPrivate();
        X509CertInfo info = new X509CertInfo();
        Date from = new Date();
        Date to = new Date(from.getTime() + (long)days * 86400000L);
        CertificateValidity interval = new CertificateValidity(from, to);
        BigInteger sn = new BigInteger(64, new SecureRandom());
        X500Name owner = new X500Name(dn);
        info.set("validity", interval);
        info.set("serialNumber", new CertificateSerialNumber(sn));
        info.set("subject", owner);
        info.set("issuer", owner);
        info.set("key", new CertificateX509Key(pair.getPublic()));
        info.set("version", new CertificateVersion(2));
        AlgorithmId algo = new AlgorithmId(AlgorithmId.SHA_oid);
        info.set("algorithmID", new CertificateAlgorithmId(algo));
        X509CertImpl cert = new X509CertImpl(info);
        cert.sign(privkey, algorithm);
        algo = (AlgorithmId)cert.get("x509.algorithm");
        info.set("algorithmID.algorithm", algo);
        cert = new X509CertImpl(info);
        cert.sign(privkey, algorithm);
        return cert;
    }

    public static boolean generateKeyStore(String filePath, String password, String dn) {
        String alias = getCNfromDN(dn);
        if (alias == null || alias.trim().isEmpty()) {
            alias = "alias";
        }

        return generateKeyStore(filePath, password, dn, alias);
    }

    public static boolean generateKeyStore(String filePath, String password, String dn, String alias) {
        return generateKeyStore(filePath, password, dn, alias, 3650);
    }

    public static boolean generateKeyStore(String filePath, String password, String dn, String alias, int days) {
        try {
            KeyPair kp = generateKeyPair();
            KeyStore ks = KeyStore.getInstance("PKCS12");
            File file = new File(filePath);
            if (file.exists()) {
                ks.load(new FileInputStream(file), password.toCharArray());
            } else {
                ks.load((InputStream)null, (char[])null);
            }

            X509Certificate cert = generateCertificate(kp, dn, days, "SHA256withDSA");
            Certificate[] chain = new Certificate[]{cert};
            ks.setKeyEntry(alias, kp.getPrivate(), password.toCharArray(), chain);
            ks.store(new FileOutputStream(file), password.toCharArray());
            return true;
        } catch (Exception var10) {
            var10.printStackTrace();
            return false;
        }
    }

    public static KeyPair generateKeyPair() {
        return generateKeyPair("RSA");
    }

    public static KeyPair generateKeyPair(String algorithm) {
        return generateKeyPair(algorithm, (String)null);
    }

    public static KeyPair generateKeyPair(String algorithm, String provider) {
        return generateKeyPair(algorithm, provider, 2048);
    }

    public static KeyPair generateKeyPair(String algorithm, String provider, int size) {
        try {
            KeyPairGenerator kpg;
            if (provider == null) {
                kpg = KeyPairGenerator.getInstance(algorithm);
            } else {
                kpg = KeyPairGenerator.getInstance(algorithm, provider);
            }

            kpg.initialize(size, new SecureRandom());
            KeyPair kp = kpg.genKeyPair();
            return kp;
        } catch (Exception var5) {
            var5.printStackTrace();
            return null;
        }
    }

    public static KeyPair generateKeyPair(int size) {
        try {
            SecureRandom sr = new SecureRandom();
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(size, sr);
            KeyPair kp = kpg.genKeyPair();
            return kp;
        } catch (Exception var4) {
            var4.printStackTrace();
            return null;
        }
    }

    public static PublicKey getPublicKey(String base64PublicKey) {
        PublicKey publicKey = null;

        try {
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(Base64.getDecoder().decode(base64PublicKey));
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            publicKey = keyFactory.generatePublic(keySpec);
            return publicKey;
        } catch (NoSuchAlgorithmException var4) {
            log.error("getPublicKey NoSuchAlgorithmException: " + var4.getMessage());
        } catch (InvalidKeySpecException var5) {
            log.error("getPublicKey InvalidKeySpecException: " + var5.getMessage());
        }

        return publicKey;
    }

    public static PrivateKey getPrivateKey(String base64PrivateKey) {
        PrivateKey privateKey = null;

        try {
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(base64PrivateKey));
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            privateKey = keyFactory.generatePrivate(keySpec);
        } catch (NoSuchAlgorithmException var4) {
            log.error("getPublicKey NoSuchAlgorithmException: " + var4.getMessage());
        } catch (InvalidKeySpecException var5) {
            log.error("getPublicKey InvalidKeySpecException: " + var5.getMessage());
        }

        return privateKey;
    }

    public static byte[] encrypt(byte[] data, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPPadding");
        OAEPParameterSpec oaepParams = new OAEPParameterSpec("SHA-256", "MGF1", new MGF1ParameterSpec("SHA-256"), PSpecified.DEFAULT);
        cipher.init(1, publicKey, oaepParams);
        return cipher.doFinal(data);
    }

    public static String encrypt(String data, String base64PublicKey) throws Exception {
        return Base64.getEncoder().encodeToString(encrypt(data.getBytes(), getPublicKey(base64PublicKey)));
    }

    public static String encrypt(String data, PublicKey publicKey) throws Exception {
        return Base64.getEncoder().encodeToString(encrypt(data.getBytes(), publicKey));
    }

    public static String encrypt(byte[] data, String base64PublicKey) throws Exception {
        return Base64.getEncoder().encodeToString(encrypt(data, getPublicKey(base64PublicKey)));
    }

    public static byte[] encrypt2Bytes(String data, String base64PublicKey) throws Exception {
        return encrypt(data.getBytes(), getPublicKey(base64PublicKey));
    }

    public static byte[] encrypt2Bytes(String data, PublicKey publicKey) throws Exception {
        return encrypt(data.getBytes(), publicKey);
    }

    public static byte[] encrypt2Bytes(byte[] data, String base64PublicKey) throws Exception {
        return encrypt(data, getPublicKey(base64PublicKey));
    }

    public static String decrypt(byte[] data, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPPadding");
        OAEPParameterSpec oaepParams = new OAEPParameterSpec("SHA-256", "MGF1", new MGF1ParameterSpec("SHA-256"), PSpecified.DEFAULT);
        cipher.init(2, privateKey, oaepParams);
        return new String(cipher.doFinal(data));
    }

    public static String decrypt(byte[] data, String base64PrivateKey) throws Exception {
        return decrypt(data, getPrivateKey(base64PrivateKey));
    }

    public static String decrypt(String base64Data, String base64PrivateKey) throws Exception {
        return decrypt(Base64.getDecoder().decode(base64Data.getBytes()), getPrivateKey(base64PrivateKey));
    }

    public static String decrypt(String base64Data, PrivateKey privateKey) throws Exception {
        return decrypt(Base64.getDecoder().decode(base64Data.getBytes()), privateKey);
    }

    public static byte[] decrypt2Bytes(byte[] data, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPPadding");
        OAEPParameterSpec oaepParams = new OAEPParameterSpec("SHA-256", "MGF1", new MGF1ParameterSpec("SHA-256"), PSpecified.DEFAULT);
        cipher.init(2, privateKey, oaepParams);
        return cipher.doFinal(data);
    }

    public static byte[] decrypt2Bytes(byte[] data, String base64PrivateKey) throws Exception {
        return decrypt2Bytes(data, getPrivateKey(base64PrivateKey));
    }

    public static byte[] decrypt2Bytes(String base64Data, String base64PrivateKey) throws Exception {
        return decrypt2Bytes(base64Data.getBytes(), getPrivateKey(base64PrivateKey));
    }

    public static byte[] decrypt2Bytes(String base64Data, PrivateKey privateKey) throws Exception {
        return decrypt2Bytes(base64Data.getBytes(), privateKey);
    }

    public static String sign(String data, String base64PrivateKey) throws Exception {
        return sign(data, getPrivateKey(base64PrivateKey));
    }

    public static String sign(String data, PrivateKey privateKey) throws Exception {
        Signature privateSignature = Signature.getInstance("SHA256withRSA");
        privateSignature.initSign(privateKey);
        privateSignature.update(data.getBytes(StandardCharsets.UTF_8));
        byte[] signature = privateSignature.sign();
        return Base64.getEncoder().encodeToString(signature);
    }

//    public static String signHash(String data, String base64PrivateKey) throws Exception {
//        String hash = SHA.sha256(data);
//        return sign(hash, getPrivateKey(base64PrivateKey));
//    }
//
//    public static String signHash(String data, PrivateKey privateKey) throws Exception {
//        String hash = SHA.sha256(data);
//        return sign(hash, privateKey);
//    }

    public static boolean verify(String data, String signature, PublicKey publicKey) throws Exception {
        Signature publicSignature = Signature.getInstance("SHA256withRSA");
        publicSignature.initVerify(publicKey);
        publicSignature.update(data.getBytes(StandardCharsets.UTF_8));
        byte[] signatureBytes = Base64.getDecoder().decode(signature);
        return publicSignature.verify(signatureBytes);
    }

    public static boolean verify(String data, String signature, String base64PublicKey) throws Exception {
        return verify(data, signature, getPublicKey(base64PublicKey));
    }

//    public static boolean verifyHash(String data, String signature, String base64PublicKey) throws Exception {
//        String hash = SHA.sha256(data);
//        return verify(hash, signature, getPublicKey(base64PublicKey));
//    }
//
//    public static boolean verifyHash(String data, String signature, PublicKey publicKey) throws Exception {
//        String hash = SHA.sha256(data);
//        return verify(hash, signature, publicKey);
//    }

//    public static String getThumbPrint(PublicKey publicKey) throws NoSuchAlgorithmException {
//        MessageDigest md = MessageDigest.getInstance("SHA-1");
//        byte[] der = publicKey.getEncoded();
//        md.update(der);
//        byte[] digest = md.digest();
//        String digestHex = Hex.encodeHexString(digest);
//        return digestHex.toLowerCase();
//    }

//    public static String getThumbPrint(String base64PublicKey) throws NoSuchAlgorithmException {
//        PublicKey publicKey = getPublicKey(base64PublicKey);
//        return getThumbPrint(publicKey);
//    }

    private static String getCNfromDN(String dn) {
        String cn = "";
        if (dn != null && !dn.isEmpty() && !dn.trim().isEmpty()) {
            String[] arr = dn.split(",");

            for(int i = 0; i < arr.length; ++i) {
                String[] arr2 = arr[i].split("=");
                if (arr2.length == 2 && "CN".equals(arr2[0])) {
                    cn = arr2[1];
                    break;
                }
            }

            return cn;
        } else {
            return cn;
        }
    }
}

