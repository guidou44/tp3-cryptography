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

    protected Map<String, String> getUserPasswordInput() {
        Scanner s = new Scanner(System.in);

        System.out.println("Enter user: ");
        String user = s.nextLine();
        System.out.println("Enter password: ");
        String password = s.nextLine();

        if (user.contains(" ") || user.length() > 20 || password.contains(" ")) {
            user = "";
            password = "";
        }

        return Collections.singletonMap(user, password);
    }

    protected String getManInTheMiddleEntry(String originalMessage, String from, String to) {
        Scanner s = new Scanner(System.in);
        System.out.printf("[MITM INTERCEPTION %s → %s] : %s%n", from, to, originalMessage);
        System.out.println("input modified message + press enter, or just press enter to keep original message:");
        return s.nextLine();
    }

    protected String getUserFromMessage(String message) {
        return message.split(" ")[0]; //si l'intru change le message lors de l'enregistrement, on assume qu'il va mettre: user password.
    }

    protected String getPasswordHashFromManInTheMiddleGetMessage(String message) {
        String[] messageParts = message.split(" "); //si l'intru change le message lors de l'enregistrement, on assume qu'il va mettre: user password.
        return messageParts.length <= 1 ? null : messageParts[1];
    }

    protected abstract String getPasswordHashFromAuthMessage(String message);

    protected int random5DigitsNumber() {
        return new Random().nextInt(99999) + 1; //on ne veut pas de 0
    }
}
