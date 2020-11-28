package ex2.common;

import ex2.domain.exceptions.InvalidChoiceException;

/*
* Enum qui contient les choix de protocole pour le premier menu quand le programme est lancé
* */
public enum ProtocolType implements ConsoleChoice {
    HTTP_DIGEST(1, "HTTP-Digest"),
    WEB_AUTH(2, "WebAuth"),
    NONE(3, "Quitter");

    private String name;
    private int entryNumber;

    ProtocolType(int entryNumber, String name) {
        this.entryNumber = entryNumber;
        this.name = name;
    }

    public int getEntryNUmber() {
        return this.entryNumber;
    }

    public String getName() {
        return this.name;
    }

    public void print() {
        System.out.println(getEntryNUmber() + " : " + getName());
    }

    /*
    * Fonction qu permet d'obtenir le protocole choisis à partir du numéro entré à la console.
    * */
    public static ProtocolType from(int number) {
        for (ProtocolType protocolType : ProtocolType.values()) {
            if (protocolType.getEntryNUmber() == number) {
                return protocolType;
            }
        }
        throw new InvalidChoiceException(String.format("no protocol correspond to choice: %d", number));
    }
}
