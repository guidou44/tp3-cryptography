package ex2.protocols;

import ex2.cryptography.AesCtr128Cipher;
import ex2.cryptography.Rsa1024Cipher;
import ex2.domain.Credential;
import ex2.protocols.base.Protocol;
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
* Classe qui permet de simuler le protocole WebAuthn
* */
public class WebAuthn extends Protocol {

    private static  final String BASE_DIRECTORY = "WebAuthn/";
    private static  final String KEY_STORE_FILE = "KeyStore.txt";

    private final Rsa1024Cipher rsa = new Rsa1024Cipher();
    private final AesCtr128Cipher aes = new AesCtr128Cipher();

    private int _serverNonce = 0;
    private int _sessionId = 0;
    private String _currentUser;
    private String _currentDomain;
    private String _currentPassword;

    /*
    * Fonction pour afficher les clef privée côté client, en fournissant le mot de passe. Si le keystore contien plusieurs users avec différents mots de passe,
    * seul les information du user courant seron lisibles.
    * */
    public void showKeyStore() throws Exception {
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
    * Fonction pour que l'utilisateur exécute une transaction. On assume qu'il est authentifié, sinon la fonction retourne.
    * */
    public void executeTransaction() throws Exception {
        if (_currentUser.isEmpty() || _currentDomain.isEmpty())
            return; //dernière authentification non réussis

        String operation = getOperationInput(); //opération entrée par utilisateur
        if (operation.isEmpty()) {
            System.out.println("Invalid operation.");
            return;
        }
        String domainUserStore = BASE_DIRECTORY + _currentDomain + ".txt";
        String userEntry = FileSystemUtil.readLineEntry(_currentUser, 0, FILE_ENTRY_SEPARATOR, domainUserStore); //information de ce user pour ce domaine

        String operationRequest = sendOperationRequest(operation);
        System.out.printf("T1. C → S : %s%n", operationRequest);

        String operationAnswer = sendOperationAnswer(operation, userEntry);
        System.out.printf("T2. S → C : %s%n", operationAnswer);


        String nonceText = getInformationFromMessage(operationAnswer, 3); //extraction du nonce Ns' du message
        if (nonceText == null) {
            System.out.println("Invalid answer from server");
            return;
        }
        String signatureRequest = sendSignatureRequestAuth(_currentDomain, _currentUser, _currentPassword, operation+nonceText);
        if (signatureRequest == null) return;
        System.out.printf("T3. C → S : %s%n", signatureRequest);

        String verifyResponse = sendVerifyResponseAuth(_currentDomain, _currentUser, _currentPassword, userEntry, signatureRequest, operation+nonceText);
        System.out.printf("T4. s → C : %s%n", verifyResponse);
    }

    /*
    * Fonction pour enregistrer un utilisateur auprès d'un domaine.
    * */
    @Override
    public void register() throws Exception {
        resetSession();
        String domain = getDomainInput(); //domaine choisis par utilisateur
        if (domain.isEmpty()) {
            System.out.println("Invalid target domain.");
            return;
        }
        String user = getUserInput(); //user choisis par utilisateur
        if (user.isEmpty()) {
            System.out.println("Invalid User.");
            return;
        }
        String password = getPasswordInput(); //password entrée par utilisateur qui permet de chiffrer la clef privée.
        if (password.isEmpty()) {
            System.out.println("Invalid password.");
            return;
        }

        String domainUserStore = BASE_DIRECTORY + domain + ".txt";
        rsa.generateNewKeyPair(); //génération d'une nouvelle pair de clef publique + privée avec RSA 1024
        Credential cred = new Credential(user, rsa.getPrivateKey(), domain);
        aes.encrypt(cred, password); //encryption du user et de la clef privée avec le password de l'utilisateur
        FileSystemUtil.appendToFile(cred.toString(), BASE_DIRECTORY + KEY_STORE_FILE); //persistence dans le 'keystore'

        String publicKeyRequest = sendPublicKey(user, domain); //envois de la clef publique au serveur
        System.out.printf("E1. C → S : %s%n", publicKeyRequest);

        String answer = sendRegisterNonceResponse(domain, user, domainUserStore); //réponse avec Nonce
        System.out.printf("E2. S → C : %s%n", answer);
        if (answer.startsWith(BAD_REQUEST))
            return; //si erreur on arrête l'exécution, Par exemple le MITM a changer le message pour quelque chose d'invalide et le serveur a répondus 400.

        String nonceText = getInformationFromMessage(answer, 1); //extraction de Ns de la réponse.
        if (nonceText == null) {
            System.out.println("Invalid response from server.");
            return;
        }

        String signatureMessage = sendSignatureRequestRegister(domain, nonceText); //RSA signature
        System.out.printf("E3. C → S : %s%n", signatureMessage);

        String verifyMessage = sendVerifyResponseRegister(user, domain, signatureMessage, domainUserStore); //RSA verification
        System.out.printf("E4. s → C : %s%n", verifyMessage);
    }

    /*
    * Fonction qui permet d'authentifier un utilisateur.
    * */
    @Override
    public boolean authenticate() throws Exception {
        resetSession();
        String domain = getDomainInput(); //domaine choisis pour authentication
        if (domain.isEmpty()) {
            System.out.println("Invalid target domain.");
            return false;
        }
        String user = getUserInput(); //user choisis pour le domaine
        if (user.isEmpty()) {
            System.out.println("Invalid User.");
            return false;
        }
        String password = getPasswordInput();// password pour déchiffrer la clef privée qui est chiffére avec AES128CTR
        if (password.isEmpty()) {
            System.out.println("Invalid password.");
            return false;
        }


        String authMessage = sendAuthRequest(domain, user);
        System.out.printf("A1. C → S : %s%n", authMessage);

        String answer;
        String receivedUser = getInformationFromMessage(authMessage, 2); //Côté serveur, extraction du user
        if (receivedUser == null) {
            answer = BAD_REQUEST + " no user provided."; //si le message a changé a cause du MITM, possibilité qu'il n'y ait pas de user dans le message
        }

        String domainUserStore = BASE_DIRECTORY + domain + ".txt"; //fichier des user du domaine target
        String userEntry = FileSystemUtil.readLineEntry(receivedUser, 0, FILE_ENTRY_SEPARATOR, domainUserStore);//entrée pour cet utilisateur dans le UserStore de ce domaine

        answer = sendAuthResponse(domain, userEntry);
        System.out.printf("A2. S → C : %s%n", answer);

        String nonceText = getInformationFromMessage(answer, 2); //extraction de la nonce Ns de la réponse du serveur
        if (nonceText == null) {
            System.out.println("Invalid response from server.");
            return false;
        }
        String signatureMessage = sendSignatureRequestAuth(domain, user, password, nonceText);//RSA signature de la nonce
        if (signatureMessage == null) return false;
        System.out.printf("A3. C → S : %s%n", signatureMessage);

        String verifyResponse = sendVerifyResponseAuth(domain, user, password, userEntry, signatureMessage, Integer.toString(_serverNonce));//RSA verify
        System.out.printf("A4. s → C : %s%n", verifyResponse);

        return verifyResponse.equals(OK);//TRUE: User est authentifié
    }

    //region PrivateMethods

    /*
    * Fonction pour l'enregistrement: génère le message E1 avec la clef publique et leuser
    * */
    private String sendPublicKey(String user, String domain) {
        String publicKey = rsa.getPublicKey(); //clef publique encodé base64
        String message = domain + FILE_ENTRY_SEPARATOR + user + FILE_ENTRY_SEPARATOR + publicKey; //construction du message
        String mitmMessage = getManInTheMiddleEntry(message, CLIENT, SERVER); //donne possibilité au MITM de le changer
        message = mitmMessage.isEmpty() ? message : mitmMessage;
        return message;
    }

    /*
    * Fonction pour l'enregistrement: E2, envois une nonce pour vérifier si la clef publique appartien au user
    * */
    private String sendRegisterNonceResponse(String domain, String user, String domainUserStore) throws IOException {

        String answer;
        String alreadyExisting = FileSystemUtil.readLineEntry(user, 0, FILE_ENTRY_SEPARATOR, domainUserStore); //vérification si le user existe déjà.
        if (alreadyExisting != null) {
            answer = BAD_REQUEST + " User already exists.";
        } else {
            _serverNonce = random5DigitsNumber();//génération d'une nonce aléatoire
            answer = domain + FILE_ENTRY_SEPARATOR + _serverNonce;
        }

        String mitmAnswer = getManInTheMiddleEntry(answer, SERVER, CLIENT); //possibilité au MITM de changer la réponse
        answer = mitmAnswer.isEmpty() ? answer : mitmAnswer;
        return answer;
    }

    /*
    * Fonction pour l'enregistrement: E3, envois de H2(nonce), signé avec la clef privée
    * */
    private String sendSignatureRequestRegister(String domain, String nonceText) throws Exception {
        String privateKey = rsa.getPrivateKey();
        String signature = rsa.sign(nonceText, privateKey); //signature RSA
        String signatureMessage = domain + FILE_ENTRY_SEPARATOR + signature;
        String mitmSignature = getManInTheMiddleEntry(signatureMessage, CLIENT, SERVER); //permet au MITM de modifier le message
        signatureMessage = mitmSignature.isEmpty() ? signatureMessage : mitmSignature;
        return signatureMessage;
    }

    /*
    * Fonction pour l'enregistrement: E4, vérification de la signature par le serveur
    * */
    private String sendVerifyResponseRegister(String user, String domain, String signatureMessage, String domainUserStore) throws Exception {
        String serverSideSignature = getInformationFromMessage(signatureMessage, 1); //extraction de la signature du mesage
        boolean verified = false;

        if (serverSideSignature != null) {
            verified = rsa.verify(Integer.toString(_serverNonce), serverSideSignature, rsa.getPublicKey());//RSA verify
            if (verified) {
                FileSystemUtil.appendToFile(user + FILE_ENTRY_SEPARATOR + rsa.getPublicKey(), domainUserStore);//La clef public appartien bien au user, on le rajoute au UserStore de ce domaine
            }
        }

        String answerSignRequest = verified ? OK : BAD_REQUEST;
        String mitmAnswer = getManInTheMiddleEntry(answerSignRequest, SERVER, CLIENT); //possibilité au MITM de changer la réponse
        answerSignRequest = mitmAnswer.isEmpty() ? answerSignRequest : mitmAnswer;
        return  answerSignRequest;
    }

    /*
    * Fonction pour authentification: A1, envois d'une demande d'authentification pour le user.
    * */
    private String sendAuthRequest(String domain, String user) {
        _sessionId = random5DigitsNumber();//génération d'un nombre aléatoire pour la session
        String authMessage = domain + FILE_ENTRY_SEPARATOR +_sessionId + FILE_ENTRY_SEPARATOR + user;
        String mitmAuthMessage = getManInTheMiddleEntry(authMessage, CLIENT, SERVER); //possibilité au MITM de changer le message
        authMessage = mitmAuthMessage.isEmpty() ? authMessage : mitmAuthMessage;
        return authMessage;
    }

    /*
    * Fonction pour authentification: A2, envois d'une demande de signature au client.
    * */
    private String sendAuthResponse(String domain, String userEntry) {
        String answer;
        if (userEntry == null) {
            answer = BAD_REQUEST + " user not registered.";//le user n'existe pas dans le 'userStore' du domaine courant
        } else {
            _serverNonce = random5DigitsNumber();//nonce aléatoire
            answer = domain + FILE_ENTRY_SEPARATOR + _sessionId + FILE_ENTRY_SEPARATOR + _serverNonce;
        }

        String mitmAnswer = getManInTheMiddleEntry(answer, SERVER, CLIENT); //possiblité au MITM de changer le message
        answer = mitmAnswer.isEmpty() ? answer : mitmAnswer;
        return answer;
    }

    /*
    * Fonctions pour authentification ET transaction: génère le message pour envoyer le paramètre 'toSign' signé avec la clef privée au serveur.
    * */
    private String sendSignatureRequestAuth(String domain, String user, String password, String toSign) throws Exception {

        String privateKey = getExistingPrivateKeyForUser(password, user); //clef privée pour ce user, déchiffrée
        if (privateKey == null) {
            System.out.println("No private key saved for user");
            return null;
        }

        String signature = rsa.sign(toSign, privateKey);//RSA sign

        String signatureMessage = domain + FILE_ENTRY_SEPARATOR + _sessionId + FILE_ENTRY_SEPARATOR + signature;
        String mitmSignatureMessage = getManInTheMiddleEntry(signatureMessage, CLIENT, SERVER);//possibilité au MITM de changer le message
        signatureMessage = mitmSignatureMessage.isEmpty() ? signatureMessage : mitmSignatureMessage;
        return signatureMessage;
    }

    /*
    * Fonctions pour authentification ET transaction: génère la réponse du serveur pour la vérification du message signée envoyé par le client
     * */
    private String sendVerifyResponseAuth(String domain, String user, String password, String userEntry, String signatureMessage, String plainText) throws Exception {
        String serverSideSignature = getInformationFromMessage(signatureMessage, 2);//extraction du message signée côté serveur
        boolean verified = false;
        String publicKey = userEntry.split(FILE_ENTRY_SEPARATOR)[1];//extraction de la clef publique de l'entrée dans le user store

        if (serverSideSignature != null) {
            verified = rsa.verify(plainText, serverSideSignature, publicKey);//RSA verify
            if (verified) {//vérification OK, sauvegarde des infos du user pour la prochaine transaction
                _currentUser = user;
                _currentDomain = domain;
                _currentPassword = password;
            }
        }

        String answerSignRequest = verified ? OK : BAD_REQUEST;
        String mitmVerifyAnswer = getManInTheMiddleEntry(answerSignRequest, SERVER, CLIENT);//possibilité au MITM de changer le message
        answerSignRequest = mitmVerifyAnswer.isEmpty() ? answerSignRequest : mitmVerifyAnswer;
        return answerSignRequest;
    }

    /*
    * Fonction pour transaction: T1, envois un requête de transaction au serveur.
    * */
    private String sendOperationRequest(String operation) {
        String operationRequest = _currentDomain + FILE_ENTRY_SEPARATOR + _sessionId + FILE_ENTRY_SEPARATOR + operation;
        String mitmOperationRequest = getManInTheMiddleEntry(operationRequest, CLIENT, SERVER); //possiblité au MITM de changer le message
        operationRequest = mitmOperationRequest.isEmpty() ? operationRequest : mitmOperationRequest;
        return  operationRequest;
    }

    /*
    * Fonction pour transaction: T2, réponse du serveur, demande d'une vérification avec Nonce
    * */
    private String sendOperationAnswer(String operation, String userEntry) {
        String operationAnswer;
        if (userEntry == null) {
            operationAnswer = BAD_REQUEST + " user not registered."; //ce user n'existe pas dans le 'userStore' du domaine courant.
        } else {
            _serverNonce = random5DigitsNumber(); //génération d'une nonce aléatoire
            operationAnswer = _currentDomain + FILE_ENTRY_SEPARATOR + _sessionId + FILE_ENTRY_SEPARATOR + operation + FILE_ENTRY_SEPARATOR + _serverNonce;
        }

        String mitmOperationAnswer = getManInTheMiddleEntry(operationAnswer, SERVER, CLIENT); //possibilité au MITM de changer le message
        operationAnswer = mitmOperationAnswer.isEmpty() ? operationAnswer : mitmOperationAnswer;
        return operationAnswer;
    }

    /*
    * Fonction qui permet de charger en mémoire tous les informations de clef privée côté client, et ce déchiffrés (user , privateKey, domaine).
    * À noter que si quelqu'un demande le KeyStore local et que celui-ci contient plusieurs user, les users qui ne sont pas le user courant seon illisibles.
    * */
    private List<Credential> loadAllSavedCredentials(String password) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        List<String> lines = FileSystemUtil.getAllLinesInFile(BASE_DIRECTORY + KEY_STORE_FILE); //load tous les ligne du fichier dans une liste
        List<Credential> credentials = new ArrayList<>();

        for (String line : lines) {
            String user = aes.decrypt(line.split(FILE_ENTRY_SEPARATOR)[1], password); //déchiffrement du user
            String privateKey = aes.decrypt(line.split(FILE_ENTRY_SEPARATOR)[2], password);//déchiffrement de la clef publique
            String domain = line.split(FILE_ENTRY_SEPARATOR)[0]; //extraction du domaine
            Credential cred = new Credential(user, privateKey, domain);
            credentials.add(cred);//ajout a la liste de credentials
        }
        return credentials;
    }

    /*
    * ré-initialise les informations de sessions (attributs de classe)
    * */
    private void resetSession() {
        _currentUser = "";
        _currentDomain = "";
        _currentPassword = "";
        _serverNonce = 0;
        _sessionId = 0;
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
     * fonction pour extraire la clef privée, déchifrée du KeyStore, pour le user spécifié avec le password spécifié.
     * */
    private String getExistingPrivateKeyForUser(String password, String user) throws Exception {
        List<Credential> credentials = loadAllSavedCredentials(password);

        for (Credential cred : credentials) {
            if (cred.getUser().equals(user))
                return cred.getPrivateKey();
        }

        return null; //ce user n'a pas de clef privée dans le keystore.
    }

    //endregion
}
