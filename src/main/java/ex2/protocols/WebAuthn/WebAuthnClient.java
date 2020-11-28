package ex2.protocols.WebAuthn;

import ex2.cryptography.AesCtr128Cipher;
import ex2.domain.Credential;
import ex2.domain.exceptions.InvalidProtocolStepException;
import ex2.protocols.base.IProtocolClient;
import ex2.protocols.base.IProtocolServer;
import ex2.protocols.base.IProtocolStep;
import ex2.utils.FileSystemUtil;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;

/*
* Class qui représente un client pour le siulateur du protocole WebAuthn
* */
public class WebAuthnClient extends WebAuthn implements IProtocolClient<IProtocolStep> {

    private static  final String KEY_STORE_FILE = "KeyStore.txt";

    private final AesCtr128Cipher aes = new AesCtr128Cipher();

    private IProtocolServer<IProtocolStep> _server;
    private String _currentPassword;

    /*
    * Fonction qui permet d'enregistrer un serveur auprès de ce client. Le design pattern 'Observer' est utilisé ici. Quand le client reçoit
    * un message du serveur, il génère sa réponse et l'envoit au serveur en générant un événement auprès de celui-ci.
    * */
    public void registerServer(IProtocolServer<IProtocolStep> server) {
        _server = server;
    }

    /*
    * Fonction qui permet d'initier les échanges pour l'enregistrement.
    * */
    public void register() throws Exception {
        printStepSeparator();
        String domain = getDomainInput();
        String user = getUserInput(); //user choisis par utilisateur
        String password = getPasswordInput();
        if (domain.isEmpty() || user.isEmpty() || password.isEmpty()) {
            System.out.println("One of the provided input was invalid. REMINDER: Spaces are not acceptable.");
            return;
        }
        _currentDomain = domain;
        _currentUser = user;
        _currentPassword = password;

        rsa.generateNewKeyPair(); //génération d'une nouvelle pair de clef publique + privée avec RSA 1024
        Credential cred = new Credential(user, rsa.getPrivateKey(), domain);
        aes.encrypt(cred, password); //encryption du user et de la clef privée avec le password de l'utilisateur
        FileSystemUtil.appendToFile(cred.toString(), BASE_DIRECTORY + KEY_STORE_FILE); //persistence dans le 'keystore'
        String publicKey = rsa.getPublicKey(); //clef publique encodé base64
        String publicKeyMessage =  domain + SEPARATOR + user + SEPARATOR + publicKey;
        _server.acceptServerSide(WebAuthnStep.E1, WebAuthnStep.E2, publicKeyMessage);
    }

    /*
    * Fonction qui permet d'initer les échanges client/server pour l'authentification.
    * */
    public boolean authenticate() throws Exception {
        printStepSeparator();
        String domain = getDomainInput();
        String user = getUserInput(); //user choisis par utilisateur
        String password = getPasswordInput();
        if (domain.isEmpty() || user.isEmpty() || password.isEmpty()) {
            System.out.println("One of the provided input was invalid. REMINDER: Spaces are not accepted.");
            return false;
        }
        _currentDomain = domain;
        _currentUser = user;
        _currentPassword = password;

        _sessionId = random5DigitsNumber();//génération d'un nombre aléatoire pour la session
        String authMessage = domain + SEPARATOR +_sessionId + SEPARATOR + user;
        _server.acceptServerSide(WebAuthnStep.A1, WebAuthnStep.A2, authMessage);
        return _currentUser != null && _currentDomain != null && _currentPassword != null;
    }

    /*
    * Fonction qui permet d'initier les échanges client/server pour faire une transaction
    * */
    public void transaction() throws Exception {
        if (_currentUser.isEmpty() || _currentDomain.isEmpty() || _sessionId == 0)
            return; //dernière authentification non réussis


        printStepSeparator();
        String operation = getOperationInput(); //opération entrée par utilisateur dans la console
        if (operation.isEmpty()) {
            System.out.println("Invalid operation.");
            return;
        }

        String request = _currentDomain + SEPARATOR + _sessionId + SEPARATOR + operation;
        _server.acceptServerSide(WebAuthnStep.T1, WebAuthnStep.T2, request);//envois au serveur
    }

    /*
     * Fonction pour afficher les clef privée côté client, en fournissant le mot de passe. Si le keystore contien plusieurs users avec différents mots de passe,
     * seul les information du user courant seron lisibles.
     * */
    public void showKeyStore() throws Exception {

        printStepSeparator();
        String password = getPasswordInput();
        if (password.isEmpty()) {
            System.out.println("Invalid password.");
            return;
        }

        List<Credential> credentials = loadAllSavedCredentials(password);

        for (Credential cred : credentials) {
            System.out.println(cred.toString());
        }
    }

    /*
     * Fonction qui est appelée quand le client reçoit un message. L'étape précédente, l'étape à exécuter et le message sont passées en paramètre.
     * */
    @Override
    public void acceptClientSide(IProtocolStep lastStep, IProtocolStep nextStep, String message) throws Exception {

        switch ((WebAuthnStep) nextStep) {

            case E3:
                if (message.startsWith(BAD_REQUEST)) {
                    resetSession();
                    return; //si erreur on arrête l'exécution, Par exemple le MITM a changer le message pour quelque chose d'invalide et le serveur a répondus 400.
                }

                printStepSeparator();
                String signatureMessageRegister = generateE3Message(message);
                if (signatureMessageRegister == null) return;
                _server.acceptServerSide(WebAuthnStep.E3, WebAuthnStep.E4, signatureMessageRegister);
                break;

            case A3:
                if (message.startsWith(BAD_REQUEST)) {
                    resetSession();
                    return;
                }
                printStepSeparator();
                String signatureMessageAuth = generateA3Message(message);
                if (signatureMessageAuth == null) return;
                _server.acceptServerSide(WebAuthnStep.A3, WebAuthnStep.A4, signatureMessageAuth);
                break;

            case T3:
                if (message.startsWith(BAD_REQUEST)) {
                    resetSession();
                    return;
                }
                printStepSeparator();
                String signatureMessageTransaction = generateT3Message(message);
                if (signatureMessageTransaction == null) return;
                _server.acceptServerSide(WebAuthnStep.T3, WebAuthnStep.T4, signatureMessageTransaction);
                break;

            case END://échange terminé
                if (lastStep.equals(WebAuthnStep.A4)) {
                    String code = getInformationFromMessage(message, 2);
                    if (code == null || !code.equals(OK)) { //authentification a échouée. On efface les infos de user, domaine, session car ils ne seront pas réutilisables
                        resetSession();
                    }
                }
                break;

            default:
                throw new InvalidProtocolStepException(String.format("Cannot execute step %s on client side", nextStep));
        }
    }

    //region private methods

    /*
     * Fonction qui permet de charger en mémoire tous les informations de clef privée côté client, et ce déchiffrés (user , privateKey, domaine).
     * À noter que si quelqu'un demande le KeyStore local et que celui-ci contient plusieurs user, les users qui ne sont pas le user courant seon illisibles.
     * */
    private List<Credential> loadAllSavedCredentials(String password) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        List<String> lines = FileSystemUtil.getAllLinesInFile(BASE_DIRECTORY + KEY_STORE_FILE); //load tous les ligne du fichier dans une liste
        List<Credential> credentials = new ArrayList<>();

        for (String line : lines) {
            String user = aes.decrypt(line.split(SEPARATOR)[1], password); //déchiffrement du user
            String privateKey = aes.decrypt(line.split(SEPARATOR)[2], password);//déchiffrement de la clef publique
            String domain = line.split(SEPARATOR)[0]; //extraction du domaine
            Credential cred = new Credential(user, privateKey, domain);
            credentials.add(cred);//ajout a la liste de credentials
        }
        return credentials;
    }

    /*
     * fonction pour aller l'opération de la console.
     * */
    private String getOperationInput() {
        System.out.println("Enter operation: ");
        String operation = scanner.nextLine();
        if (operation.contains(" ") || operation.length() > 50) {
            operation = ""; //l'opération doit avoir 50 charactères ou moins et NE PAS contenir d'espaces
        }
        return operation;
    }

    /*
     * fonction pour aller le domaine de la console.
     * */
    private String getDomainInput() {
        System.out.println("Enter target domain: ");
        String domain = scanner.nextLine();
        if (domain.contains(" ") || domain.length() > 50) {
            domain = ""; //le domaine doit avoir 50 charactères ou moins et NE PAS contenir d'espaces
        }
        return domain;
    }

    /*
     * fonction pour extraire la clef privée, déchiffrée du KeyStore, pour le user spécifié avec le password spécifié.
     * */
    private String getExistingPrivateKeyForUser(String user, String password) throws Exception {
        List<Credential> credentials = loadAllSavedCredentials(password);

        for (Credential cred : credentials) {
            if (cred.getUser().equals(user))
                return cred.getPrivateKey();
        }

        return null; //ce user n'a pas de clef privée dans le keystore.
    }

    /*
     * Fonction qui génère le message du client à l'étape T3
     * */
    private String generateA3Message(String message) throws Exception {
        String nonceText = getInformationFromMessage(message, 2); //extraction du nonce Ns du message
        if (nonceText == null) {
            System.out.println("Invalid answer from server");
            return null;
        }
        String signature = generateSignature(nonceText);
        return _currentDomain + SEPARATOR + _sessionId + SEPARATOR + signature;
    }

    /*
    * Fonction qui génère le message du client à l'étape T3
    * */
    private String generateT3Message(String message) throws Exception {
        String nonceText = getInformationFromMessage(message, 3); //extraction du nonce Ns' du message
        String operation = getInformationFromMessage(message, 2); //extraction de l'opération du message
        if (nonceText == null || operation == null) {
            System.out.println("Invalid answer from server");
            return null;
        }
        String signature = generateSignature(operation + nonceText);
        return _currentDomain + SEPARATOR + _sessionId + SEPARATOR + signature;
    }

    /*
     * Fonction pour l'enregistrement: E3, génère H2(nonce), signé avec la clef privée
     * */
    private String generateE3Message(String message) throws Exception {
        String nonceText = getInformationFromMessage(message, 1); //extraction de Ns de la réponse.
        if (nonceText == null) {
            System.out.println("Invalid response from server.");
            return null;
        }
        String signature = generateSignature(nonceText);
        if (signature == null) return null;
        return _currentDomain + SEPARATOR + signature;
    }

    /*
    * Fonction qui génère une signature avec la clef privée du user courant pour le String passé en paramètre.
    * */
    private String generateSignature(String toSign) throws Exception {
        String privateKey = getExistingPrivateKeyForUser(_currentUser, _currentPassword);
        if (privateKey == null) {
            System.out.println("No private key saved for user");
            return null;
        }
        return rsa.sign(toSign, privateKey);
    }

    /*
     * ré-initialise les informations de sessions (attributs de classe)
     * */
    private void resetSession() {
        _currentUser = null;
        _currentDomain = null;
        _currentPassword = null;
        _sessionId = 0;
    }

    //endregion
}
