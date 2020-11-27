package ex2.cryptography;

import ex2.domain.Credential;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.Map;

/**
 * Cette classe est un 'wrapper' pour le cipher AES-CTR-128.
 * Elle encapsule les details de l'implémentation.
 * */
public class AesCtr128Cipher {

    private static final String ALGORITHM_NAME = "AES";
    private static final String CIPHER_NAME = "AES/CTR/NoPadding";
    private static final String IV_SEPARATOR = "ØØØØØØØØ";

    /**
     * Fonction pour encrypter un nouveau credential avec le password passé en paramètre.
     * */
    public void encrypt(Credential credentialToEncrypt, String externalPassword)
            throws IOException, NoSuchAlgorithmException, NoSuchPaddingException,
            InvalidAlgorithmParameterException, InvalidKeyException,
            BadPaddingException, IllegalBlockSizeException {

        SecretKey secretKey = generateSecretKeyFromPassword(externalPassword);//génère une clef à partir du password
        IvParameterSpec userIv = generateInitialisationVector(); //génère un IV aléatoire pour le champ 'user'
        IvParameterSpec passwordIv = generateInitialisationVector();//génère un IV aléatoire pour le champ 'privateKey'

        String userEncrypted = encryptSingleField(credentialToEncrypt.getUser(), secretKey, userIv); //champ 'user' encrypté
        String passwordEncrypted = encryptSingleField(credentialToEncrypt.getPrivateKey(), secretKey, passwordIv);//champ 'password' encrypté

        credentialToEncrypt.setUser(userEncrypted);//on set le champ 'user' encrypté. Le iv est concaténé avec le cipher text pour assurer le déchiffrement.
        credentialToEncrypt.setPrivateKey(passwordEncrypted);//on set le champ 'password' encrypté. Le iv est concaténé avec le cipher text pour assurer le déchiffrement.
    }

    /**
     * Fonction qui encrypte un seul champ string. Puisqu'il faut garder le iv, la stratégie est de concatémer le IV
     * avec le string chiffré, en mettant un separateur connue entre les 2. Il sera plus facile de reconstruire les composantes
     * au déchiffrement.
     * */
    private String encryptSingleField(String fieldToEncrypt, SecretKey secretKey, IvParameterSpec iv)
            throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
            InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance(CIPHER_NAME); //instanciation du cipher
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, iv); //initialisation avec la clef et le iv, en mode encryption
        byte[] fieldBytes = fieldToEncrypt.getBytes(StandardCharsets.UTF_8);
        byte[] encryptedFieldBytes = cipher.doFinal(fieldBytes);
        return Base64.getEncoder().encodeToString(encryptedFieldBytes) + IV_SEPARATOR + Base64.getEncoder().encodeToString(iv.getIV());
    }

    /**
     * Fonction qui décrypte un seule champ chiffré.
     * */
    public String decrypt(String parameterToDecryptRaw, String externalPassword)
            throws UnsupportedEncodingException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        SecretKey secretKey = generateSecretKeyFromPassword(externalPassword); //génère la clef à partir du password
        Map<String, IvParameterSpec> fieldAndIv = extractFieldAndIvFromRawEncryptedField(parameterToDecryptRaw);
        Map.Entry<String, IvParameterSpec> entry = fieldAndIv.entrySet().iterator().next();
        String pureEncryptedField = entry.getKey(); //séparation du champ
        IvParameterSpec iv = entry.getValue();//séparation du iv

        Cipher cipher = Cipher.getInstance(CIPHER_NAME);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, iv);//initialier la clé, iv et indiquer qu'il s'agit d'un déchifrement
        byte[] encryptedBytes = Base64.getDecoder().decode(pureEncryptedField);//Décoder le message chiffré de sa forme base64
        return new String(cipher.doFinal(encryptedBytes), StandardCharsets.UTF_8); //conversion en string claire
    }

    /**
     * Fonction pour générer la clef.
     * On génère une clef à partir du password. La stratégie est de générer un Hash avec SHA-256 à partir du password claire.
     * On tronque ensuite ce hash à 128 bits.
     * */
    private SecretKey generateSecretKeyFromPassword(String password) throws NoSuchAlgorithmException, UnsupportedEncodingException {
        byte[] key = Base64.getDecoder().decode(HashManager.hashSHA256(password).getBytes());
        key = Arrays.copyOf(key, 16); //on prend seulement les 128 premier bits pour AES-CTR-128
        return new SecretKeySpec(key, ALGORITHM_NAME);
    }

    /**
     * Fonction pour générer un IV aléatoire
     * */
    private IvParameterSpec generateInitialisationVector() {

        SecureRandom random = new SecureRandom();    //Créer une instance d'un générateur aléatoire sécuritaire
        byte[] iv0 = random.generateSeed(16);    //générer iv aléatoirement de 16 octets
        return new IvParameterSpec(iv0);
    }

    /**
     * Fonction pour extraire le champ chiffré et son IV d'un champ passé en paramètre
     * */
    private Map<String, IvParameterSpec> extractFieldAndIvFromRawEncryptedField(String fieldAndIv) {
        String[] temp = fieldAndIv.split(IV_SEPARATOR, 2); //on extrait le IV qui a été placé a la fin du field avec, séparé par le sépareteur
        IvParameterSpec iv = reconstructIv(temp[1]);//on le convertit en IvParameter spec utilisable
        return Collections.singletonMap(temp[0], iv);
    }

    /**
     * Fonction pour reconstruire le IvParameter à partir du iv string encodé en base 64.
     * */
    private IvParameterSpec reconstructIv(String iv) {
        byte[] decodedIv = Base64.getDecoder().decode(iv); // decode le IV encodé en base64
        return new IvParameterSpec(decodedIv);// reconstruire le IV
    }
}
