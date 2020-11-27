package ex2.protocols.base;

import java.util.Collections;
import java.util.Map;
import java.util.Random;
import java.util.Scanner;

/*
* Classe de base pour les simulateurs de protocoles. Contient des constantes et des méthodes partagées.
* */
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

    public abstract void register() throws Exception; //doit être implémenté par n'importe qu'elle simulateur de protocole
    public abstract boolean authenticate() throws Exception;//doit être implémenté par n'importe qu'elle simulateur de protocole

    protected final Scanner scanner = new Scanner(System.in);//permet de lire la console

    /*
    * Fonction qui permet d'extraire les infos de user et de password de la console
    * */
    protected Map<String, String> getUserPasswordInput() {

        String user = getUserInput();
        String password = getPasswordInput();

        return Collections.singletonMap(user, password);
    }

    /*
     * Fonction qui permet d'extraire le user de la console
     * */
    protected String getUserInput() {
        System.out.println("Enter user: ");
        String user = scanner.nextLine();
        if (user.contains(" ") || user.length() > 20) {
            user = "";//le user doit avoir 20 charactères ou moins et NE PAS avoir d'espace
        }
        return user;
    }

    /*
     * Fonction qui permet d'extraire le password de la console
     * */
    protected String getPasswordInput() {
        System.out.println("Enter password: ");
        String password = scanner.nextLine();
        if (password.contains(" ")) {
            password = "";//le password ne dois pas avoir d'espace
        }
        return password;
    }

    /*
     * Fonction qui permet à l'intrus ou MITM de changer des message interceptés. retourne le message modifié, ou un string vide si gardé tel quel.
     * */
    protected String getManInTheMiddleEntry(String originalMessage, String from, String to) {
        Scanner s = new Scanner(System.in);
        System.out.printf("[MITM INTERCEPTION %s → %s] : %s%n", from, to, originalMessage);
        System.out.println("input modified message + press enter, or just press enter to keep original message:");
        return s.nextLine();
    }

    /*
    * Fonction qui permet d'extraire de l'info d'un message reçus, à l'index désiré
    * */
    protected String getInformationFromMessage(String message, int atIndex) {
        String[] messageParts = message.split(" ");
        return messageParts.length < atIndex + 1 ? null : messageParts[atIndex];
    }


    /*
    * Fonction qui permet de générer un Integer aléatoire à 5 chiffres différent de 0.
    * */
    protected int random5DigitsNumber() {
        return new Random().nextInt(99999) + 1; //on ne veut pas de 0
    }
}
