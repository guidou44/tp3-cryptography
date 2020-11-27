package ex2.protocols;

import ex2.cryptography.HashManager;
import ex2.protocols.base.Protocol;
import ex2.utils.FileSystemUtil;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.util.Map;

/*
* Classe qui permet de simuler le protocole HttpDigest
* */
public class HttpDigest extends Protocol {

    private static final String UserDbFileName = "HttpDigest/HttpDigestUser.txt";

    private int _serverNonce = 0;
    private int _sessionId = 0;
    private int _clientNonce = 0;

    /*
    * Fonction pour l'étape d'enregistrement avec HttpDigest
    * */
    @Override
    public void register() throws Exception {
        Map.Entry<String, String> userPassword = getUserPasswordInput().entrySet().iterator().next(); //extraction des infos de user et password de la console
        if (userPassword.getKey().isEmpty() || userPassword.getValue().isEmpty()) {
            System.out.println("Invalid user or password.");
            return;
        }

        String user = userPassword.getKey();
        String password = userPassword.getValue();

        String hash = HashManager.hashMD5(user + HASH_SEPARATOR + password); //création du hash avec user et password
        String lineEntry = user + FILE_ENTRY_SEPARATOR + hash;
        String mitmMessage = getManInTheMiddleEntry(lineEntry, CLIENT, SERVER);//possibilité au MITM de changer lemessage

        if (!mitmMessage.isEmpty()) {
            lineEntry = mitmMessage;
            user = getInformationFromMessage(mitmMessage, 0);//extraction du user qui a été changé par le MITM
            hash = getInformationFromMessage(mitmMessage, 1);//extraction du password qui a été changé par le MITM
        }
        System.out.printf("E1. C → S : %s%n", lineEntry);

        String answer;
        String alreadyExisting = FileSystemUtil.readLineEntry(user, 0, FILE_ENTRY_SEPARATOR, UserDbFileName);
        if (alreadyExisting != null) {
            answer = BAD_REQUEST + " User already exist.";//cet utilisateur existe déjà côté serveur
        } else if (hash == null) {
            answer = BAD_REQUEST + "Invalid password.";//le hash n'est pas dans le message: possible si le MITM a changer le message incorrectement
        } else {
            answer = OK;
            FileSystemUtil.appendToFile(lineEntry, UserDbFileName); //Ajout au 'UserStore' du serveur
        }

        mitmMessage = getManInTheMiddleEntry(answer, SERVER, CLIENT); //possibilité au MITM de changer la réponse
        System.out.printf("E2. S → C : %s%n", mitmMessage.isEmpty() ? answer : mitmMessage);
    }

    /*
     * Fonction pour l'étape d'authentification avec HttpDigest
     * */
    @Override
    public boolean authenticate() throws Exception {
        resetSession(); //réinitialise la session d'abord
        getRequest(); //HTTP_GET non authentifiée
        return authenticateInternal(); //authentification
    }

    /*
    * Fonction pour extraire la partie 'hash' du message d'authentification
    * */
    protected String getPasswordHashFromAuthMessage(String message) {
        String[] messageParts = message.split(" ");
        return messageParts.length <= 3 ? null : messageParts[3];
    }

    /*
     * Fonction pour faire la requête HTTP GET initiale (non authentifié)
     * */
    private void getRequest() {
        String clientGetRequest = GET + DOMAIN;
        String mitmMessage = getManInTheMiddleEntry(clientGetRequest, CLIENT, SERVER); //possibilité au MITM de changer le message
        String getAnswer;
        if (!mitmMessage.isEmpty()) {
            getAnswer = NOT_FOUND + "Not found";
            System.out.printf("A1. C → S : %s%n", mitmMessage);
            String mitmBadAnswer = getManInTheMiddleEntry(getAnswer, SERVER, CLIENT);
            System.out.printf("A2. S → C : %s%n", mitmBadAnswer.isEmpty() ? getAnswer : mitmBadAnswer);
            //on ne peut pas savoir ce que le MITM a mis comme message, donc on retourne NOT_FOUND car un seul domaine de suporté et seulement HTTP GET de supporté
            return;
        }

        System.out.printf("A1. C → S : %s%n", clientGetRequest);
        _serverNonce = random5DigitsNumber(); //nonce aléatoire
        _sessionId = random5DigitsNumber();//session Id aléatoire
        getAnswer = String.format("%s Unauthorized %d %d", UNAUTHORIZED, _serverNonce, _sessionId);
        String mitmAnswer = getManInTheMiddleEntry(getAnswer, SERVER, CLIENT); //possibilité au MITM de changer la réponse
        if (!mitmAnswer.isEmpty()) {
            resetSession(); //on ne veut pas avoir de nonce pour que le programme se termine si le MITM a modifié cette réponse.
        }
        System.out.printf("A2. S → C : %s%n", mitmAnswer.isEmpty() ? getAnswer : mitmAnswer);
    }

    /*
    * Fonction pour autentification du client auprès du serveur.
    * */
    private boolean authenticateInternal() throws NoSuchAlgorithmException, IOException {
        if (_serverNonce == 0 || _sessionId == 0) {
            //l'intrus a modifié la réponse du serveur de la requête GET, on ne peut pas savoir ce qu'il a modifié. le programme se termine.
            return false;
        }

        Map.Entry<String, String> userPassword = getUserPasswordInput().entrySet().iterator().next(); //extraction des information user et password de la console
        if (userPassword.getKey().isEmpty() || userPassword.getValue().isEmpty()) {
            System.out.println("Invalid user or password.");
            return false;
        }
        String user = userPassword.getKey();
        String password = userPassword.getValue();


        String innerHash = HashManager.hashMD5(user + HASH_SEPARATOR + password); //génération du hash interne
        _clientNonce = random5DigitsNumber();//génération de la nonce aléatoire côté client
        String authHashClient = generateAuthHash(user, innerHash); //génération du hash externe
        String authMessage = String.format("%s %d %d %s %d", user, _serverNonce, _clientNonce, authHashClient, _sessionId);
        String mitmMessage = getManInTheMiddleEntry(authMessage, CLIENT, SERVER);//possibilité au MITM de changer le message
        authMessage = mitmMessage.isEmpty() ? authMessage : mitmMessage;
        System.out.printf("A3. C → S : %s%n", authMessage);

        String answer;
        String userReceived = getInformationFromMessage(authMessage, 0);//extraction du user dans le message envoyé par le client
        String passwordHashReceived = getPasswordHashFromAuthMessage(authMessage);//extraction du hash dans le message envoyé par le client

        String alreadyExisting = FileSystemUtil.readLineEntry(userReceived, 0, FILE_ENTRY_SEPARATOR, UserDbFileName);//extraction des infos du user du 'UserStore' du serveur
        boolean authenticated = false;
        if (alreadyExisting == null || passwordHashReceived == null) {
            answer = UNAUTHORIZED + "Unauthorized."; //on ne veut pas informer l'utilisateur que ce user n'existe pas ou que le password est invalide, par sécurité contre les intrus.
        } else {

            String innerHashServer = alreadyExisting.split(FILE_ENTRY_SEPARATOR)[1];//extraction du hash sauvegardé dans l'entré du 'UserStore'
            String authHashServer = generateAuthHash(userReceived, innerHashServer);//génération du HASH avec MD5 côté serveur
            answer = authHashServer.equals(authHashClient) ? OK + " <content requested>":  UNAUTHORIZED + "Unauthorized."; //vérfication que les hash concordes
            authenticated = true;
        }

        String mitmAnswer = getManInTheMiddleEntry(answer, SERVER, CLIENT);//possibilité au MITM de changer la réponse.
        System.out.printf("A4. S → C : %s%n", mitmAnswer.isEmpty() ? answer : mitmAnswer);

        return authenticated;
    }

    /*
    * Fonction pour générer le Hash de l'étape d'authentification. On doit fournir en paramètre le hash interne, soit H1(user:password)
    * */
    private String generateAuthHash(String user, String passwordHash) throws NoSuchAlgorithmException {
        String requestHash = HashManager.hashMD5(GET + HASH_SEPARATOR + DOMAIN);
        return HashManager.hashMD5(passwordHash + HASH_SEPARATOR + _serverNonce + HASH_SEPARATOR + _clientNonce + HASH_SEPARATOR + requestHash);
    }

    private void resetSession() {
        _serverNonce = 0;
        _clientNonce = 0;
        _sessionId = 0;
    }
}
