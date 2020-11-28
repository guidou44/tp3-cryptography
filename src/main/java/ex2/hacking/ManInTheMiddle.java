package ex2.hacking;

import ex2.protocols.base.IProtocolClient;
import ex2.protocols.base.IProtocolServer;
import ex2.protocols.base.IProtocolStep;

import java.util.Scanner;

/*
* Classe qui encapsule l'intrus. Il intercepte les message et peut les modifier à sa guise.
* L'idée est qu'il implémente les interfaces d'observeur autant comme client et comme serveur. Ainsi,
* il peut s'enregistrer comme serveur auprès du client et comme client auprès du serveur.
* Il agit donc comme 'Proxy' entre les 2, permettant à l'utilisateur du programme de modifier le message.
* Il redirrige ensuite le message au destinatère originel.
* L'idée ici est d'utiliser le 'Design pattern' du déorateur pour augmenter les fonctionnalités des observeurs qui
* sont le client ou le serveur.
* */
public class ManInTheMiddle implements IProtocolClient<IProtocolStep>, IProtocolServer<IProtocolStep> {

    private static final String INTERCEPT_HEADER = "[MESSAGE INTERCEPTION]";

    private final IProtocolClient<IProtocolStep> _client;
    private final IProtocolServer<IProtocolStep> _server;

    public ManInTheMiddle(IProtocolClient<IProtocolStep> client, IProtocolServer<IProtocolStep> server) {
        _client = client;
        _server = server;
    }

    /*
    * Fonction qui intercepte les messages envoyés au client
    * */
    @Override
    public void acceptClientSide(IProtocolStep lastStep, IProtocolStep nextStep, String message) throws Exception {
        System.out.println(INTERCEPT_HEADER + "(S→C) : " + message);
        message = modifyMessage(message);
        System.out.println(lastStep.toStringWithMessage(message));//on imprime à la console l'échange entre le client et le serveur
        _client.acceptClientSide(lastStep, nextStep, message);
    }

    /*
     * Fonction qui intercepte les messages envoyés au serveur
     * */
    @Override
    public void acceptServerSide(IProtocolStep lastStep, IProtocolStep nextStep, String message) throws Exception {
        System.out.println(INTERCEPT_HEADER + "(C→S) : " + message);
        message = modifyMessage(message);
        System.out.println(lastStep.toStringWithMessage(message));//on imprime à la console l'échange entre le serveur et le client
        _server.acceptServerSide(lastStep, nextStep, message);
    }

    /*
     * Fonction qui permet à l'intrus ou MITM de changer des message interceptés. retourne le message modifié, ou un string vide si gardé tel quel.
     * */
    private String getManInTheMiddleEntry() {
        Scanner s = new Scanner(System.in);
        System.out.println("input modified message + press enter, or just press enter to keep original message:");
        return s.nextLine();
    }

    /*
    * Fonction qui permet à l'utilisateur du programme de modifier le message intercepté ou de le laisser tel quel au choix.
    * */
    private String modifyMessage(String message) {
        String modifiedEntry = getManInTheMiddleEntry();
        return modifiedEntry.isEmpty() ? message : modifiedEntry;
    }
}
