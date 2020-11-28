package ex2.protocols.WebAuthn;

import ex2.domain.exceptions.InvalidProtocolStepException;
import ex2.protocols.base.IProtocolClient;
import ex2.protocols.base.IProtocolServer;
import ex2.protocols.base.IProtocolStep;
import ex2.utils.FileSystemUtil;

import java.io.IOException;

/*
* Classe qui représente le serveur, peut importe le domaine, pour le simulateur du protocole WebAuthn
* */
public class WebAuthnServer extends WebAuthn implements IProtocolServer<IProtocolStep> {

    private String _currentOperation;
    private String _currentPublicKey;//sert à entreposer temporairement la clef publique en attendant de voir si elle appartient vraiment au user.
    private int _serverNonce = 0;
    private IProtocolClient<IProtocolStep> _client;

    /*
     * Fonction qui permet d'enregistrer un client auprès du serveur. Le design pattern 'Observer' est utilisé ici. Quand le serveur reçoit
     * un message du client, il génère sa réponse et l'envoit au client en générant un événement auprès de celui-ci.
     * */
    public void registerClient(IProtocolClient<IProtocolStep> client) {
        _client = client;
    }

    /*
    * Fonction qui est appelée quand le serveur reçoit un message. L'étape précédente, l'étape à exécuter et le message sont passées en paramètre.
    * */
    @Override
    public void acceptServerSide(IProtocolStep lastStep, IProtocolStep nextStep, String message) throws Exception {
        switch ((WebAuthnStep) nextStep) {

            case A2:
                printStepSeparator();
                String authResponse = generateA2Message(message);
                _client.acceptClientSide(WebAuthnStep.A2, WebAuthnStep.A3, authResponse);
                break;

            case A4:
                printStepSeparator();
                String verifyResponseAuth = generateA4Message(message);

                _client.acceptClientSide(WebAuthnStep.A4, WebAuthnStep.END, verifyResponseAuth);
                break;

            case E2:
                printStepSeparator();
                String registerResponse = generateE2Message(message);
                _client.acceptClientSide(WebAuthnStep.E2, WebAuthnStep.E3, registerResponse);
                break;

            case E4:
                printStepSeparator();
                String verifyResponseRegister = generateE4Message(message);
                if (verifyResponseRegister.endsWith(OK)) {//persistence du user dans le 'UserStore' du domaine courant
                    FileSystemUtil.appendToFile(_currentUser + SEPARATOR + _currentPublicKey, BASE_DIRECTORY + _currentDomain+ ".txt");
                }
                _client.acceptClientSide(WebAuthnStep.E4, WebAuthnStep.END, verifyResponseRegister);
                break;

            case T2:
                printStepSeparator();
                String operationAnswer = generateT2Message(message);
                _client.acceptClientSide(WebAuthnStep.T2, WebAuthnStep.T3, operationAnswer);
                break;

            case T4:
                printStepSeparator();
                String verifyResponseTransaction = generateT4Message(message);
                _client.acceptClientSide(WebAuthnStep.T4, WebAuthnStep.END, verifyResponseTransaction);
                break;

            default:
                throw new InvalidProtocolStepException(String.format("Cannot execute step %s on server side", nextStep));
        }
    }

    //region PrivateMethods

    /*
    * Fonction pour aller chercher l'entrée d'information (user + publicKey) d'un user dans le 'UserStore' du domaine spécifié. Retourne null si le user est absent.
    * */
    private String getUserEntryInDomainUserStore(String targetDomain, String targetUser) throws IOException {
        String domainUserStore = BASE_DIRECTORY + targetDomain + ".txt";
        return FileSystemUtil.readLineEntry(targetUser, 0, SEPARATOR, domainUserStore);
    }

    /*
    * Fonction pour générer le message côté serveur à l'étape T2.
    * */
    private String generateT2Message(String message) throws IOException {
        String userEntry = getUserEntryInDomainUserStore(_currentDomain, _currentUser);
        String operation = getInformationFromMessage(message, 2);
        String operationAnswer;
        if (userEntry == null) {
            operationAnswer = BAD_REQUEST + " user not registered."; //ce user n'existe pas dans le 'userStore' du domaine courant.
        } else if (operation == null) {
            operationAnswer = BAD_REQUEST + " no operation provided to server"; //le message ne contient pas d'opération. P-e y a-t-il un intrus qui modifie les messages ?.
        } else {
            _serverNonce = random5DigitsNumber(); //génération d'une nonce aléatoire
            operationAnswer = _currentDomain + SEPARATOR + _sessionId + SEPARATOR + operation + SEPARATOR + _serverNonce;
        }

        _currentOperation = operation; //sauvegarde de lòpération courante côté serveur
        return operationAnswer;
    }

    /*
    * Fonction pour générer le message à l'étape E2, côté serveur.
    * */
    private String generateE2Message(String message) throws IOException {
        //Extraction des paramètre de la requête
        String user = getInformationFromMessage(message, 1);
        String domain = getInformationFromMessage(message, 0);
        String publicKey = getInformationFromMessage(message, 2);
        String authResponse;
        if (user == null || domain == null || publicKey == null) {
            authResponse = BAD_REQUEST;
        } else {
            authResponse = generateE2MessageInternal(user, domain);
        }
        _currentPublicKey = publicKey; //entreposage temporaire en attendant la vérification.
        _currentDomain = domain;
        _currentUser = user;
        return authResponse;
    }

    /*
     * Fonction pour l'enregistrement: génère le message pour E2 qui contient une nonce pour vérifier si la clef publique appartient bien au user
     * */
    private String generateE2MessageInternal(String user, String domain) throws IOException {

        String domainUserStore = BASE_DIRECTORY + domain + ".txt";
        String answer;
        String alreadyExisting = FileSystemUtil.readLineEntry(user, 0, SEPARATOR, domainUserStore); //vérification si le user existe déjà.
        if (alreadyExisting != null) {
            answer = BAD_REQUEST + " User already exists.";
        } else {
            _serverNonce = random5DigitsNumber();//génération d'une nonce aléatoire
            answer = domain + SEPARATOR + _serverNonce;

        }
        return answer;
    }

    /*
     * Fonctions pour vérification de signature: génère la réponse du serveur pour la vérification du message signée envoyé par le client
     * */
    private String generateVerifyMessage(String domain, String signature, String plainText) throws Exception {
        String userEntry = getUserEntryInDomainUserStore(domain, _currentUser);
        boolean verified = false;
        String publicKey = userEntry.split(SEPARATOR)[1];//extraction de la clef publique de l'entrée dans le user store

        if (signature != null) {
            verified = rsa.verify(plainText, signature, publicKey);//RSA verify
            if (!verified) {//vérification MAUVAISE, reset les infos car l'authentification ne se poursuivera pas.
                resetSession();
            }
        }

        return verified ? OK : BAD_REQUEST;
    }

    /*
     * Fonctions pour vérification de signature: génère la réponse du serveur pour la vérification du message signée envoyé par le client pour un client
     * qui n'est pas encore persisté dans le 'DomainUserStore'.
     * */
    private String generateVerifyMessage(String domain, String signature, String plainText, String publicKey) throws Exception {
        boolean verified = rsa.verify(plainText, signature, publicKey);//RSA verify
        if (!verified) {//vérification MAUVAISE, reset les infos car l'authentification ne se poursuivera pas.
            resetSession();
        }

        return verified ? OK : BAD_REQUEST;
    }

    /*
    * Fonction pour générer le message de l'étape A2 côté serveur
    * */
    private String generateA2Message(String message) throws IOException {
        String answer;
        String user = getInformationFromMessage(message, 2); //Côté serveur, extraction du user
        String domain = getInformationFromMessage(message, 0); //Côté serveur, extraction du user
        if (user == null || domain == null) {
            answer = BAD_REQUEST + " no user or domain provided"; //si le message a changé a cause du MITM, possibilité qu'il n'y ait pas de user ou de domaine dans le message
        }

        _currentUser = user;
        _currentDomain = domain;

        String domainUserStore = BASE_DIRECTORY + domain + ".txt"; //fichier des user du domaine target
        String userEntry = FileSystemUtil.readLineEntry(user, 0, SEPARATOR, domainUserStore);//entrée pour cet utilisateur dans le UserStore de ce domaine
        if (userEntry == null) {
            answer = BAD_REQUEST + " user not registered.";//le user n'existe pas dans le 'userStore' du domaine courant
        } else {
            _serverNonce = random5DigitsNumber();//nonce aléatoire
            _sessionId = random5DigitsNumber();//sessionID aléatoire
            answer = domain + SEPARATOR + _sessionId + SEPARATOR + _serverNonce;
        }
        return answer;
    }

    /*
    * Fonction pour générer le message de l'étape T4 côté serveur
    * */
    private String generateT4Message(String message) throws Exception {
        String signature = getInformationFromMessage(message, 2);//extraction signature du message
        String verifyAnswer;
        if (signature == null) {
            verifyAnswer = BAD_REQUEST;
        } else {
            verifyAnswer = generateVerifyMessage(_currentDomain, signature, _currentOperation + _serverNonce);
        }
        return verifyAnswer.equals(OK) ? _currentDomain + SEPARATOR + verifyAnswer : verifyAnswer;
    }

    /*
    * Fonction pour générer le message de l'étape E4 côté serveur.
    * */
    private String generateE4Message(String message) throws Exception {
        //extraction des paramètre du message
        String domain = getInformationFromMessage(message, 0);
        String signature = getInformationFromMessage(message, 1);
        String verifyAnswer;
        if (signature == null || domain == null) {
            verifyAnswer = BAD_REQUEST;
        } else {
            verifyAnswer = generateVerifyMessage(domain, signature, Integer.toString(_serverNonce), _currentPublicKey);
        }

        return verifyAnswer.equals(OK) ? _currentDomain + SEPARATOR + verifyAnswer : verifyAnswer;
    }

    /*
     * Fonction pour générer le message de l'étape A4 côté serveur.
     * */
    private String generateA4Message(String message) throws Exception {
        //extraction des paramètre du message
        String domain = getInformationFromMessage(message, 0);
        String signature = getInformationFromMessage(message, 2);
        String verifyAnswer;
        if (signature == null || domain == null) {
            verifyAnswer = BAD_REQUEST;
        } else {
            verifyAnswer = generateVerifyMessage(domain, signature, Integer.toString(_serverNonce));
        }

        return verifyAnswer.equals(OK) ? _currentDomain + SEPARATOR + _sessionId + SEPARATOR + verifyAnswer : verifyAnswer;
    }

    private void resetSession() {
        _currentUser = null;
        _currentDomain = null;
        _currentPublicKey = null;
        _currentOperation = null;
    }
    //endregion
}
