package ex2.protocols.HttpDigest;

import ex2.domain.exceptions.InvalidProtocolStepException;
import ex2.protocols.base.IProtocolClient;
import ex2.protocols.base.IProtocolServer;
import ex2.protocols.base.IProtocolStep;
import ex2.utils.FileSystemUtil;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;

public class HttpDigestServer extends HttpDigest implements IProtocolServer<IProtocolStep> {

    private static final String UserDbFileName = "HttpDigest/HttpDigestUser.txt";

    private IProtocolClient<IProtocolStep> _client;
    private int _serverNonce = 0;
    private int _sessionId = 0;

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
        switch ((HttpDigestStep) nextStep) {

            case E2:
                printStepSeparator();
                String answer = generateE2Message(message);
                _client.acceptClientSide(HttpDigestStep.E2, HttpDigestStep.END, answer);
                break;

            case A2:
                printStepSeparator();
                String getAnswer = generateA2Message(message);
                _client.acceptClientSide(HttpDigestStep.A2, HttpDigestStep.A3, getAnswer);
                break;

            case A4:
                printStepSeparator();
                String answerAuth = generateA4Message(message);
                _client.acceptClientSide(HttpDigestStep.A4, HttpDigestStep.END, answerAuth);
                break;

            default:
                throw new InvalidProtocolStepException(String.format("Cannot execute step %s on server side", nextStep));
        }

    }

    /*
    * Fonction pour générer le message de l'étape E2 côté serveur.
    * */
    private String generateE2Message(String message) throws IOException {
        String user = getInformationFromMessage(message, 0);//extraction du user
        String hash = getInformationFromMessage(message, 1);//extraction du password
        String answer;
        if (user == null || hash == null) {
            answer = BAD_REQUEST + "Invalid user or password hash.";//le hash ou le user ne sont pas dans le message: possible si le MITM a changé le message incorrectement
        } else {
            String alreadyExistingUser = FileSystemUtil.readLineEntry(user, 0, SEPARATOR, UserDbFileName);
            if (alreadyExistingUser != null) {
                answer = BAD_REQUEST + " User already exist.";//cet utilisateur existe déjà côté serveur
            } else {
                answer = OK;
                FileSystemUtil.appendToFile(message, UserDbFileName); //Ajout au 'UserStore' du serveur
            }

        }
        return answer;
    }

    /*
    * Fonction pour générer le message à l'étape A2 côté serveur.
    * */
    private String generateA2Message(String message) {
        _serverNonce = random5DigitsNumber(); //nonce aléatoire
        _sessionId = random5DigitsNumber();//session Id aléatoire
        String httpVerb = getInformationFromMessage(message, 0);
        String resource = getInformationFromMessage(message, 1);
        String getAnswer;
        if (httpVerb == null || resource == null) {
            getAnswer = NOT_FOUND;  //seulement GET au domaine est supporté pour ce serveur
        } else {
            getAnswer =  UNAUTHORIZED + SEPARATOR + "Unauthorized" + SEPARATOR + _serverNonce + SEPARATOR + _sessionId;
        }
        return getAnswer;
    }

    /*
    * Fonction pour générer le message de l'étape A4 côté serveur.
    * */
    private String generateA4Message(String message) throws IOException, NoSuchAlgorithmException {
        String answer;
        String userReceived = getInformationFromMessage(message, 0);//extraction du user dans le message envoyé par le client
        String passwordHashReceived = getInformationFromMessage(message, 3);//extraction du hash dans le message envoyé par le client
        String clientNonceText = getInformationFromMessage(message, 2);
        ;
        if (userReceived == null || passwordHashReceived == null || clientNonceText == null) {
            answer = BAD_REQUEST;
        } else {
            String alreadyExisting = FileSystemUtil.readLineEntry(userReceived, 0, SEPARATOR, UserDbFileName);//extraction des infos du user du 'UserStore' du serveur
            if (alreadyExisting == null) {
                answer = UNAUTHORIZED  + SEPARATOR +  "Unauthorized."; //on ne veut pas informer l'utilisateur que ce user n'existe pas ou que le password est invalide, par sécurité contre les intrus.
            } else {
                String innerHashServer = alreadyExisting.split(SEPARATOR)[1];//extraction du hash sauvegardé dans l'entré du 'UserStore'
                String authHashServer = generateAuthHash(innerHashServer, Integer.toString(_serverNonce), clientNonceText);//génération du HASH avec MD5 côté serveur
                answer = authHashServer.equals(passwordHashReceived) ? OK + " <content requested>":  UNAUTHORIZED + "Unauthorized."; //vérfication que les hash concordes
            }
        }
        return answer;
    }
}
