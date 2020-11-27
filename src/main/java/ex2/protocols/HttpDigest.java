package ex2.protocols;

import ex2.cryptography.HashManager;
import ex2.protocols.base.Protocol;
import ex2.utils.FileSystemUtil;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.util.Map;

public class HttpDigest extends Protocol {

    private static final String FILE_ENTRY_SEPARATOR = " ";
    private static final String HASH_SEPARATOR = ":";
    private static final String UserDbFileName = "HttpDigestUser.txt";

    private int _serverNonce = 0;
    private int _sessionId = 0;
    private int _clientNonce;

    public void register() throws NoSuchAlgorithmException, IOException {
        Map.Entry<String, String> userPassword = getUserPasswordInput().entrySet().iterator().next();
        if (userPassword.getKey().isEmpty() || userPassword.getValue().isEmpty()) {
            System.out.println("Invalid user or password.");
            return;
        }

        String user = userPassword.getKey();
        String password = userPassword.getValue();

        String hash = HashManager.hash(user + HASH_SEPARATOR + password);
        String lineEntry = user + FILE_ENTRY_SEPARATOR + hash;
        String mitmMessage = getManInTheMiddleEntry(lineEntry, CLIENT, SERVER);

        if (!mitmMessage.isEmpty()) {
            lineEntry = mitmMessage;
            user = getUserFromMessage(mitmMessage);
            hash = getPasswordHashFromManInTheMiddleGetMessage(mitmMessage);
        }
        System.out.printf("E1. C → S : %s%n", lineEntry);

        String answer;
        String alreadyExisting = FileSystemUtil.readLineEntry(user, UserDbFileName);
        if (alreadyExisting != null) {
            answer = BAD_REQUEST + " User already exist.";
        } else if (hash == null) {
            answer = BAD_REQUEST + "Invalid password.";
        } else {
            answer = OK;
            FileSystemUtil.appendToFile(lineEntry, UserDbFileName);
        }

        mitmMessage = getManInTheMiddleEntry(answer, SERVER, CLIENT);
        System.out.printf("E2. S → C : %s%n", mitmMessage.isEmpty() ? answer : mitmMessage);
    }

    public void authenticate() throws IOException, NoSuchAlgorithmException {
        resetSession();
        getRequest();
        authenticateInternal();
    }

    private void getRequest() {
        String clientGetRequest = GET + DOMAIN;
        String mitmMessage = getManInTheMiddleEntry(clientGetRequest, CLIENT, SERVER);
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
        _serverNonce = random5DigitsNumber();
        _sessionId = random5DigitsNumber();
        getAnswer = String.format("%s Unauthorized %d %d", UNAUTHORIZED, _serverNonce, _sessionId);
        String mitmAnswer = getManInTheMiddleEntry(getAnswer, SERVER, CLIENT);
        if (!mitmAnswer.isEmpty()) {
            resetSession(); //on ne veut pas avoir de nonce pour que le programme se termine si le MITM a modifié cette réponse.
        }
        System.out.printf("A2. S → C : %s%n", mitmAnswer.isEmpty() ? getAnswer : mitmAnswer);
    }

    private void authenticateInternal() throws NoSuchAlgorithmException, IOException {
        if (_serverNonce == 0 || _sessionId == 0) {
            //l'intrus a modifié la réponse du serveur de la requête GET, on ne peut pas savoir ce qu'il a modifié. le programme se termine.
            return;
        }

        Map.Entry<String, String> userPassword = getUserPasswordInput().entrySet().iterator().next();
        if (userPassword.getKey().isEmpty() || userPassword.getValue().isEmpty()) {
            System.out.println("Invalid user or password.");
            return;
        }
        String user = userPassword.getKey();
        String password = userPassword.getValue();


        String innerHash = HashManager.hash(user + HASH_SEPARATOR + password);
        _clientNonce = random5DigitsNumber();
        String authHashClient = generateAuthHash(user, innerHash);
        String authMessage = String.format("%s %d %d %s %d", user, _serverNonce, _clientNonce, authHashClient, _sessionId);
        String mitmMessage = getManInTheMiddleEntry(authMessage, CLIENT, SERVER);
        authMessage = mitmMessage.isEmpty() ? authMessage : mitmMessage;
        System.out.printf("A3. C → S : %s%n", authMessage);

        String answer;
        String userReceived = getUserFromMessage(authMessage);
        String passwordHashReceived = getPasswordHashFromAuthMessage(authMessage);

        String alreadyExisting = FileSystemUtil.readLineEntry(userReceived, UserDbFileName);
        if (alreadyExisting == null || passwordHashReceived == null) {
            answer = UNAUTHORIZED + "Unauthorized."; //on ne veut pas informer le user que ce user n'existe pas ou que le password est invalide.
        } else {

            String innerHashServer = alreadyExisting.split(FILE_ENTRY_SEPARATOR)[1];
            String authHashServer = generateAuthHash(userReceived, innerHashServer);
            answer = authHashServer.equals(authHashClient) ? OK + " <content requested>":  UNAUTHORIZED + "Unauthorized.";
        }

        String mitmAnswer = getManInTheMiddleEntry(answer, SERVER, CLIENT);
        System.out.printf("A4. S → C : %s%n", mitmAnswer.isEmpty() ? answer : mitmAnswer);
    }

    private String generateAuthHash(String user, String passwordHash) throws NoSuchAlgorithmException {
        String requestHash = HashManager.hash(GET + HASH_SEPARATOR + DOMAIN);
        return HashManager.hash(passwordHash + HASH_SEPARATOR + _serverNonce + HASH_SEPARATOR + _clientNonce + HASH_SEPARATOR + requestHash);
    }

    private void resetSession() {
        _serverNonce = 0;
        _clientNonce = 0;
        _sessionId = 0;
    }

    @Override
    protected String getPasswordHashFromAuthMessage(String message) {
        String[] messageParts = message.split(" ");
        return messageParts.length <= 3 ? null : messageParts[3];
    }
}
