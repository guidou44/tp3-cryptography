package ex2.common;

import ex2.domain.exceptions.InvalidChoiceException;


/*
* Enum qui contient les choix du second menu après avoir choisis le protocole (premier menu d'action)
* */
public enum FirstMenuAction implements ConsoleChoice {

    REGISTER(1, "Enregistrer un nouveau compte"),
    AUTHENTICATE(2, "Authentification"),
    BACK(3, "Menu précédent"),
    QUIT(4, "Quitter");

    private final int entryNumber;
    private final String name;

    FirstMenuAction(int entryNumber, String name) {
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
    * Fonction qui permet d'obtenir la valeur du choix dans l'enum à partir du numéro entré
    * */
    public static FirstMenuAction from(int number) {
        for (FirstMenuAction action : FirstMenuAction.values()) {
            if (action.getEntryNUmber() == number) {
                return action;
            }
        }
        throw new InvalidChoiceException(String.format("nothing correspond to choice: %d", number));
    }
}
