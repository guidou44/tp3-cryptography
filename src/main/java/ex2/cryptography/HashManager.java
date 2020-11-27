package ex2.cryptography;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class HashManager {

    private static final String SHA256 = "SHA-256";
    private static final String MD5 = "SHA-256";

    public static String hashMD5(String beforeHash) throws NoSuchAlgorithmException {
        return hash(beforeHash, MD5);
    }

    public static String hashSHA256(String beforeHash) throws NoSuchAlgorithmException {
        return hash(beforeHash, SHA256);
    }

    private static String hash(String beforeHash, String algorithm) throws NoSuchAlgorithmException {
        byte[] bytes = beforeHash.getBytes(StandardCharsets.UTF_8);
        MessageDigest hash = MessageDigest.getInstance(algorithm);
        bytes = hash.digest(bytes);
        return Base64.getEncoder().encodeToString(bytes);
    }
}
