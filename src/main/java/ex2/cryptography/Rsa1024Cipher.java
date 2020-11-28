package ex2.cryptography;

import javax.crypto.Cipher;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/*
* Classe qui encapsule les opérations avec RSA1024
* */
public class Rsa1024Cipher {

    private static final int keySize = 1024;//longueur de la clef
    private static final String RSA = "RSA";
    private static final String SIGNATURE= "SHA256withRSA";

    private PrivateKey _privateKey;
    private PublicKey _publicKey;

    /*
    * Fonction qui permet de générer une nouvelle pair de clef publique et privée
    * */
    public void generateNewKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance(RSA);
        keyGen.initialize(keySize);
        KeyPair pair = keyGen.generateKeyPair();
        this._privateKey = pair.getPrivate();
        this._publicKey = pair.getPublic();
    }

    /*
    * Fonction qui permet de signer le paramètre 'plainText' avec la clef privée 'privateKeyBase64' qui est un string en base 64.
    * */
    public String sign(String plainText, String privateKeyBase64) throws Exception {
        Signature privateSignature = Signature.getInstance(SIGNATURE);
        PrivateKey privateKey = privateKeyFrom(privateKeyBase64);//on reconstruit l'objet PrivateKey
        privateSignature.initSign(privateKey);
        privateSignature.update(plainText.getBytes());

        byte[] signature = privateSignature.sign();

        return Base64.getEncoder().encodeToString(signature);//encodage Base64
    }

    /*
     * Fonction qui permet de vérifier la 'signature' RSA avec la signature de 'plainText' signé avec la clef publique 'publicKeyBase64' qui est un string en base 64.
     * */
    public boolean verify(String plainText, String signature, String publicKeyBase64) throws Exception {
        Signature publicSignature = Signature.getInstance(SIGNATURE);
        PublicKey publicKey = publicKeyFrom(publicKeyBase64);//on reconstruit l'objet PublicKey
        publicSignature.initVerify(publicKey);
        publicSignature.update(plainText.getBytes());
        byte[] signatureBytes = Base64.getDecoder().decode(signature);
        return publicSignature.verify(signatureBytes);
    }

    /*
     * Fonction qui permet de reconstruire la clef publique à partir de sa représentation en String base 64
     * */
    public PublicKey publicKeyFrom(String base64StringPublicKey) throws Exception {
        PublicKey publicKey = null;
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(Base64.getDecoder().decode(base64StringPublicKey.getBytes()));
        KeyFactory keyFactory = KeyFactory.getInstance(RSA);
        publicKey = keyFactory.generatePublic(keySpec);
        return publicKey;
    }

    /*
     * Fonction qui permet de reconstruire la clef privée à partir de sa représentation en String base 64
     * */
    public PrivateKey privateKeyFrom(String base64StringPrivateKey) throws Exception {
        PrivateKey privateKey = null;
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(base64StringPrivateKey.getBytes()));
        KeyFactory keyFactory = KeyFactory.getInstance(RSA);
        privateKey = keyFactory.generatePrivate(keySpec);
        return privateKey;
    }

    public String getPrivateKey() {
        return Base64.getEncoder().encodeToString(_privateKey.getEncoded());
    }

    public String getPublicKey() {
        return Base64.getEncoder().encodeToString(_publicKey.getEncoded());
    }
}
