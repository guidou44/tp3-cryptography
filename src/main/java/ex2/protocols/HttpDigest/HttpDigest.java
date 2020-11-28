package ex2.protocols.HttpDigest;

import ex2.cryptography.HashManager;
import ex2.protocols.base.Protocol;
import ex2.utils.FileSystemUtil;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;

/*
 * Classe qui abstract qui contient certaine variables, méthodes et constantes que le client et le serveur de HttpDigest ont en commun.
 * À noter qu'ils ne partagent pas les mêmes instances de ces variables, sauf pour les constantes.
 * */
public abstract class HttpDigest extends Protocol {

    protected static final String HASH_SEPARATOR = ":";

    /*
     * Fonction pour générer le Hash de l'étape d'authentification. On doit fournir en paramètre le hash interne, soit H1(user:password)
     * */
    protected String generateAuthHash(String passwordHash, String serverNonce, String clientNonce) throws NoSuchAlgorithmException {
        String requestHash = HashManager.hashMD5(GET + HASH_SEPARATOR + DOMAIN);
        return HashManager.hashMD5(passwordHash + HASH_SEPARATOR + serverNonce + HASH_SEPARATOR + clientNonce + HASH_SEPARATOR + requestHash);
    }

}
