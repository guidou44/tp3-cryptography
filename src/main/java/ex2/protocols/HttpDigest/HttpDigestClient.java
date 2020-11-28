package ex2.protocols.HttpDigest;

import ex2.cryptography.HashManager;
import ex2.domain.exceptions.InvalidProtocolStepException;
import ex2.protocols.base.IProtocolClient;
import ex2.protocols.base.IProtocolServer;
import ex2.protocols.base.IProtocolStep;

import java.util.Map;

public class HttpDigestClient extends HttpDigest implements IProtocolClient<IProtocolStep> {

    private IProtocolServer<IProtocolStep> _server;
    private int _clientNonce = 0;

    /*
     * Fonction qui permet d'enregistrer un serveur auprès de ce client. Le design pattern 'Observer' est utilisé ici. Quand le client reçoit
     * un message du serveur, il génère sa réponse et l'envoit au serveur en générant un événement auprès de celui-ci.
     * */
    public void registerServer(IProtocolServer<IProtocolStep> server) {
        _server = server;
    }

    /*
     * Fonction pour l'étape d'enregistrement avec HttpDigest. Cette fonction initie l'échange client/serveur.
     * */
    public void register() throws Exception {
        printStepSeparator();
        Map.Entry<String, String> userPassword = getUserPasswordInput().entrySet().iterator().next(); //extraction des infos de user et password de la console
        if (userPassword.getKey().isEmpty() || userPassword.getValue().isEmpty()) {
            System.out.println("Invalid user or password.");
            return;
        }
        String user = userPassword.getKey();
        String password = userPassword.getValue();
        String hash = HashManager.hashMD5(user + HASH_SEPARATOR + password); //création du hash avec user et password
        String registerMessage = user + SEPARATOR + hash;
        _server.acceptServerSide(HttpDigestStep.E1, HttpDigestStep.E2, registerMessage);
    }

    /*
     * Fonction pour l'étape d'authentification avec HttpDigest. Cette fonction initie l'échange client/serveur
     * */
    public void authenticate() throws Exception {
        resetSession();
        printStepSeparator();
        String clientGetRequest = GET + SEPARATOR + DOMAIN;
        _server.acceptServerSide(HttpDigestStep.A1, HttpDigestStep.A2, clientGetRequest);
    }

    /*
     * Fonction qui est appelée quand le client reçoit un message. L'étape précédente, l'étape à exécuter et le message sont passées en paramètre.
     * */
    @Override
    public void acceptClientSide(IProtocolStep lastStep, IProtocolStep nextStep, String message) throws Exception {
        switch ((HttpDigestStep) nextStep) {

            case A3:
                if (message.startsWith(BAD_REQUEST))
                    break;
                printStepSeparator();
                String serverNonceText = getInformationFromMessage(message, 2);
                String sessionId = getInformationFromMessage(message, 3);
                if (sessionId == null || serverNonceText == null) {
                    System.out.println("Received invalid message from server");
                    return;
                }
                Map.Entry<String, String> userPassword = getUserPasswordInput().entrySet().iterator().next(); //extraction des information user et password de la console
                if (userPassword.getKey().isEmpty() || userPassword.getValue().isEmpty()) {
                    System.out.println("Invalid user or password.");
                    return;
                }
                String user = userPassword.getKey();
                String password = userPassword.getValue();
                String innerHash = HashManager.hashMD5(user + HASH_SEPARATOR + password); //génération du hash interne
                _clientNonce = random5DigitsNumber();//génération de la nonce aléatoire côté client
                String authHashClient = generateAuthHash(innerHash, serverNonceText, Integer.toString(_clientNonce)); //génération du hash externe
                String authMessage = user + SEPARATOR + serverNonceText + SEPARATOR + _clientNonce + SEPARATOR + authHashClient + SEPARATOR + sessionId;
                _server.acceptServerSide(HttpDigestStep.A3, HttpDigestStep.A4, authMessage);
                break;

            case END:
                break;

            default:
                throw new InvalidProtocolStepException(String.format("Cannot execute step %s on server side", nextStep));
        }
    }

    private void resetSession() {
        _clientNonce = 0;
    }
}
