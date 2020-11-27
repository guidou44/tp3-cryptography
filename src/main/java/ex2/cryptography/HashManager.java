package ex2.cryptography;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class HashManager {

    private static final String SHA1 = "SHA-1";

    public static String hash(String beforeHash) throws NoSuchAlgorithmException {
        byte[] bytes = beforeHash.getBytes(StandardCharsets.UTF_8);
        MessageDigest sha1 = MessageDigest.getInstance(SHA1);
        bytes = sha1.digest(bytes);
        return Base64.getEncoder().encodeToString(bytes);
    }
}
