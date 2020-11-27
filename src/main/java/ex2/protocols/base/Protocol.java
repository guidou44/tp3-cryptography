package ex2.protocols.base;

import java.util.Collections;
import java.util.Map;
import java.util.Random;
import java.util.Scanner;

public abstract class Protocol {

    protected static  final String OK = "200";
    protected static final String BAD_REQUEST = "400";
    protected static final String UNAUTHORIZED = "401";
    protected static final String NOT_FOUND = "404";
    protected static final String DOMAIN = "/dir/index.html";
    protected static final String GET = "GET";
    protected static final String CLIENT = "C";
    protected static final String SERVER = "S";
    protected static final String FILE_ENTRY_SEPARATOR = " ";
    protected static final String HASH_SEPARATOR = ":";

    public abstract void register() throws Exception;
    public abstract void authenticate() throws Exception;

    private final Scanner scanner = new Scanner(System.in);

    protected Map<String, String> getUserPasswordInput() {

        String user = getUserInput();
        String password = getPasswordInput();

        return Collections.singletonMap(user, password);
    }

    protected String getUserInput() {
        System.out.println("Enter user: ");
        String user = scanner.nextLine();
        if (user.contains(" ") || user.length() > 20) {
            user = "";
        }
        return user;
    }

    protected String getPasswordInput() {
        System.out.println("Enter password: ");
        String password = scanner.nextLine();
        if (password.contains(" ")) {
            password = "";
        }
        return password;
    }

    protected String getManInTheMiddleEntry(String originalMessage, String from, String to) {
        Scanner s = new Scanner(System.in);
        System.out.printf("[MITM INTERCEPTION %s → %s] : %s%n", from, to, originalMessage);
        System.out.println("input modified message + press enter, or just press enter to keep original message:");
        return s.nextLine();
    }

    protected String getInformationFromMessage(String message, int atIndex) {
        String[] messageParts = message.split(" ");
        return messageParts.length < atIndex + 1 ? null : messageParts[atIndex];
    }

    protected int random5DigitsNumber() {
        return new Random().nextInt(99999) + 1; //on ne veut pas de 0
    }
}
