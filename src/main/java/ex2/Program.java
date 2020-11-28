package ex2;

import ex2.common.AuthMenuAction;
import ex2.common.ConsoleChoice;
import ex2.common.FirstMenuAction;
import ex2.common.ProtocolType;
import ex2.hacking.ManInTheMiddle;
import ex2.protocols.HttpDigest.HttpDigestClient;
import ex2.protocols.HttpDigest.HttpDigestServer;
import ex2.protocols.WebAuthn.WebAuthnClient;
import ex2.protocols.WebAuthn.WebAuthnServer;

import java.util.Arrays;
import java.util.Comparator;
import java.util.List;
import java.util.Scanner;
import java.util.stream.Collectors;

/*
* Programme principal
* */
public class Program {

    private static boolean Continue = true;
    private static int MenuNumber = 0;
    private static final int NoChoice = -1;
    private static ProtocolType _protocol = ProtocolType.NONE;
    private static boolean authenticated = false;
    private static FirstMenuAction firstMenuAction = null;
    private static WebAuthnClient webAuthClient = null;

    public static void main(String[] args) {

        try {
            /*
            * Listes de tous les menus. Les éléments sont ordonnées en ordre de leur numéro de choix.
            * */
            List<ProtocolType> orderedProtocolTypes = Arrays.stream(ProtocolType.values()).sorted(Comparator.comparing(ProtocolType::getEntryNUmber)).collect(Collectors.toList());
            List<FirstMenuAction> firstMenu = Arrays.stream(FirstMenuAction.values()).sorted(Comparator.comparing(FirstMenuAction::getEntryNUmber)).collect(Collectors.toList());
            List<AuthMenuAction> authMenu = Arrays.stream(AuthMenuAction.values()).sorted(Comparator.comparing(AuthMenuAction::getEntryNUmber)).collect(Collectors.toList());

            while (Continue) {

                if (MenuNumber == 0) { //premier menu
                    System.out.println("Choisir protocole : ");
                    int protocolNumber = getChoiceFromUser(orderedProtocolTypes);
                    _protocol = ProtocolType.from(protocolNumber == NoChoice ? ProtocolType.NONE.getEntryNUmber() : protocolNumber);
                    MenuNumber++;
                }


                if (_protocol == ProtocolType.HTTP_DIGEST) {
                    HttpDigestClient client = new HttpDigestClient();
                    HttpDigestServer server = new HttpDigestServer();
                    ManInTheMiddle manInTheMiddle = new ManInTheMiddle(client, server);
                    client.registerServer(manInTheMiddle);//enregistrement de l'intrus comme client auprès su serveur
                    server.registerClient(manInTheMiddle);//enregistrement de l'intrus comme serveur auprès du client

                    System.out.println("Choisir action : ");
                    int firstActionNumber = getChoiceFromUser(firstMenu);
                    FirstMenuAction action = FirstMenuAction.from(firstActionNumber == NoChoice ? FirstMenuAction.QUIT.getEntryNUmber() : firstActionNumber);

                    if (action == FirstMenuAction.REGISTER) {
                        client.register();
                        Continue = true;
                    } else if (action == FirstMenuAction.AUTHENTICATE) {
                        client.authenticate();
                        Continue = true;
                    } else if (action == FirstMenuAction.BACK) {
                        Continue = true;
                        MenuNumber = 0;
                    } else {
                        Continue = false;
                        System.out.println("Bye!");
                    }
                } else if (_protocol == ProtocolType.WEB_AUTH) {

                    if (!authenticated) {
                        webAuthClient = new WebAuthnClient();
                        WebAuthnServer server = new WebAuthnServer();
                        ManInTheMiddle manInTheMiddle = new ManInTheMiddle(webAuthClient, server);
                        webAuthClient.registerServer(manInTheMiddle);//enregistrement de l'intrus comme client auprès su serveur
                        server.registerClient(manInTheMiddle);//enregistrement de l'intrus comme serveur auprès du client
                        System.out.println("Choisir action : ");
                        int firstActionNumber = getChoiceFromUser(firstMenu);
                        firstMenuAction = FirstMenuAction.from(firstActionNumber == NoChoice ? FirstMenuAction.QUIT.getEntryNUmber() : firstActionNumber);
                    }

                    if (firstMenuAction == FirstMenuAction.REGISTER && webAuthClient != null) {
                        webAuthClient.register();
                        Continue = true;
                    } else if (firstMenuAction == FirstMenuAction.AUTHENTICATE && webAuthClient != null) {
                        if (!authenticated) {
                            authenticated = webAuthClient.authenticate();
                        }

                        if (authenticated) {//user déjà authentifié
                            System.out.println("Choisir action : ");
                            int secondMenuActionNumber = getChoiceFromUser(authMenu);
                            AuthMenuAction authMenuAction = AuthMenuAction.from(secondMenuActionNumber == NoChoice ? AuthMenuAction.QUIT.getEntryNUmber() : secondMenuActionNumber);

                            if (authMenuAction == AuthMenuAction.QUIT) {
                                Continue = false;
                                System.out.println("Bye!");
                            } else if (authMenuAction == AuthMenuAction.OPERATION) {
                                webAuthClient.transaction();
                                Continue = true;
                            } else if (authMenuAction == AuthMenuAction.KEY_STORE) {
                                webAuthClient.showKeyStore();
                                Continue = true;
                            } else if (authMenuAction == AuthMenuAction.BACK) {
                                authenticated = false;
                            }
                        }

                    } else if (firstMenuAction == FirstMenuAction.BACK) {
                        Continue = true;
                        MenuNumber = 0;
                    } else {
                        Continue = false;
                        System.out.println("Bye!");
                    }

                } else {
                    Continue = false;
                    System.out.println("Bye!");
                }
            }
        } catch (Exception ex) {
            System.out.println("An exception was thrown.");
            System.out.println(ex.getMessage());
        }

    }

    /*
    * Fonction qui retourne l'enum correspondant au choix de l'utilisateur qui est un chiffre
    * */
    private static <T extends ConsoleChoice> int getChoiceFromUser(List<T> elements) {
        for (T element : elements) {
            element.print();
        }

        Scanner s = new Scanner(System.in);
        String next = s.nextLine();
        if (next.isEmpty()) {
            return NoChoice;
        }
        return  Integer.parseInt(next);
    }

}
