package ex2.protocols;

import ex2.cryptography.AesCtr128Cipher;
import ex2.cryptography.Rsa1024Cipher;
import ex2.domain.Credential;
import ex2.protocols.base.Protocol;
import ex2.utils.FileSystemUtil;

import java.io.IOException;
import java.util.Scanner;

public class WebAuthn extends Protocol {

    private static  final String BASE_DIRECTORY = "WebAuthn/";
    private static  final String KEY_STORE_FILE = "KeyStore.txt";

    private final Rsa1024Cipher rsa = new Rsa1024Cipher();
    private final AesCtr128Cipher aes = new AesCtr128Cipher();

    private int _serverNonce = 0;
    private int _sessionId = 0;

    @Override
    public void register() throws Exception {
        String user = getUserInput();
        if (user.isEmpty()) {
            System.out.println("Invalid User.");
            return;
        }
        String domain = getDomainInput();
        if (domain.isEmpty()) {
            System.out.println("Invalid target domain.");
            return;
        }
        String password = getPasswordInput();
        if (password.isEmpty()) {
            System.out.println("Invalid password.");
            return;
        }

        String domainUserStore = BASE_DIRECTORY + domain + ".txt";
        rsa.generateNewKeyPair();
        Credential cred = new Credential(user, rsa.getPrivateKey(), domain);
        aes.encrypt(cred, password);
        FileSystemUtil.appendToFile(cred.toString(), BASE_DIRECTORY + KEY_STORE_FILE);

        sendPublicKey(user, domain);
        String answer = answerWithNonce(domain, user, domainUserStore);
        if (answer.startsWith(BAD_REQUEST))
            return;

        String nonceText = getInformationFromMessage(answer, 1);
        if (nonceText == null) {
            System.out.println("Invalid response from server.");
            return;
        }

        String signatureMessage = sendSignature(domain, nonceText);

        verifySignature(user, domain, signatureMessage, domainUserStore);
    }

    private void verifySignature(String user, String domain, String signatureMessage, String domainUserStore) throws Exception {
        String serverSideSignature = getInformationFromMessage(signatureMessage, 1);
        boolean verified = false;


        if (serverSideSignature != null) {
            verified = rsa.verify(Integer.toString(_serverNonce), serverSideSignature, rsa.getPublicKey());
            if (verified) {
                FileSystemUtil.appendToFile(user + FILE_ENTRY_SEPARATOR + rsa.getPublicKey(), domainUserStore);
            }
        }

        String answerSignRequest = verified ? OK : BAD_REQUEST;
        String mitmAnswer = getManInTheMiddleEntry(answerSignRequest, SERVER, CLIENT);
        answerSignRequest = mitmAnswer.isEmpty() ? answerSignRequest : mitmAnswer;
        System.out.printf("E4. s → C : %s%n", answerSignRequest);
    }

    private String sendSignature(String domain, String nonceText) throws Exception {
        String privateKey = rsa.getPrivateKey();
        String signature = rsa.sign(nonceText, privateKey);
        String signatureMessage = domain + FILE_ENTRY_SEPARATOR + signature;
        String mitmSignature = getManInTheMiddleEntry(signatureMessage, CLIENT, SERVER);
        signatureMessage = mitmSignature.isEmpty() ? signatureMessage : mitmSignature;
        System.out.printf("E3. C → S : %s%n", signatureMessage);
        return signatureMessage;
    }

    private String answerWithNonce(String domain, String user, String domainUserStore) throws IOException {

        String answer;
        String alreadyExisting = FileSystemUtil.readLineEntry(user, domainUserStore);
        if (alreadyExisting != null) {
            answer = BAD_REQUEST + " User already exists.";
        } else {
            _serverNonce = random5DigitsNumber();
            answer = domain + FILE_ENTRY_SEPARATOR + _serverNonce;
        }

        String mitmAnswer = getManInTheMiddleEntry(answer, SERVER, CLIENT);
        answer = mitmAnswer.isEmpty() ? answer : mitmAnswer;
        System.out.printf("E2. S → C : %s%n", answer);
        return answer;
    }

    private void sendPublicKey(String user, String domain) {
        String publicKey = rsa.getPublicKey();
        String message = domain + FILE_ENTRY_SEPARATOR + user + FILE_ENTRY_SEPARATOR + publicKey;
        String mitmMessage = getManInTheMiddleEntry(message, CLIENT, SERVER);
        message = mitmMessage.isEmpty() ? message : mitmMessage;
        System.out.printf("E1. C → S : %s%n", message);
    }

    @Override
    public void authenticate() throws Exception {
        String user = getUserInput();
        if (user.isEmpty()) {
            System.out.println("Invalid User.");
            return;
        }
        String domain = getDomainInput();
        if (domain.isEmpty()) {
            System.out.println("Invalid target domain.");
            return;
        }

        String domainUserStore = BASE_DIRECTORY + domain + ".txt";
        _sessionId = random5DigitsNumber();
        String authMessage = domain + FILE_ENTRY_SEPARATOR +_sessionId + FILE_ENTRY_SEPARATOR + user;
        String mitmAuthMessage = getManInTheMiddleEntry(authMessage, CLIENT, SERVER);
        authMessage = mitmAuthMessage.isEmpty() ? authMessage : mitmAuthMessage;
        System.out.printf("A1. C → S : %s%n", authMessage);

        String answer;
        String receivedUser = getInformationFromMessage(authMessage, 2);
        if (receivedUser == null) {
            answer = BAD_REQUEST + " no user provided.";
        }

        String userEntry = FileSystemUtil.readLineEntry(receivedUser, domainUserStore);
        if (userEntry == null) {
            answer = BAD_REQUEST + " user not registered.";
        } else {
            _serverNonce = random5DigitsNumber();
            answer = domain + FILE_ENTRY_SEPARATOR + _sessionId + FILE_ENTRY_SEPARATOR + _serverNonce;
        }

        String mitmAnswer = getManInTheMiddleEntry(answer, SERVER, CLIENT);
        answer = mitmAnswer.isEmpty() ? answer : mitmAnswer;
        System.out.printf("A2. S → C : %s%n", answer);

        String nonceText = getInformationFromMessage(answer, 2);
        if (nonceText == null) {
            System.out.println("Invalid response from server.");
            return;
        }

        String keyEntry = FileSystemUtil.readLineEntry(user, BASE_DIRECTORY + KEY_STORE_FILE);
        if (keyEntry == null) {
            System.out.println("No private key saved for user");
            return;
        }

        String privateKey = keyEntry.split(" ")[0];
        String signature = rsa.sign(nonceText, privateKey);

        String signatureMessage = domain + FILE_ENTRY_SEPARATOR + _sessionId + FILE_ENTRY_SEPARATOR + signature;
        String mitmSignatureMessage = getManInTheMiddleEntry(signatureMessage, CLIENT, SERVER);
        signatureMessage = mitmSignatureMessage.isEmpty() ? signatureMessage : mitmSignatureMessage;
        System.out.printf("A3. C → S : %s%n", signatureMessage);

        String serverSideSignature = getInformationFromMessage(signatureMessage, 2);
        boolean verified = false;
        String publicKey = userEntry.split(FILE_ENTRY_SEPARATOR)[1];

        if (serverSideSignature != null) {
            verified = rsa.verify(Integer.toString(_serverNonce), serverSideSignature, publicKey);
        }

        String answerSignRequest = verified ? OK : BAD_REQUEST;
        String mitmVerifyAnswer = getManInTheMiddleEntry(answerSignRequest, SERVER, CLIENT);
        answerSignRequest = mitmVerifyAnswer.isEmpty() ? answerSignRequest : mitmVerifyAnswer;
        System.out.printf("A4. s → C : %s%n", answerSignRequest);
    }

    public void showKeyStore() throws Exception {

    }

    private void resetSession() {
        _serverNonce = 0;
        _sessionId = 0;
    }

    private String getDomainInput() {
        Scanner scanner = new Scanner(System.in);
        System.out.println("Enter target domain: ");
        String domain = scanner.nextLine();
        if (domain.contains(" ") || domain.length() > 50) {
            domain = "";
        }
        return domain;
    }
}
