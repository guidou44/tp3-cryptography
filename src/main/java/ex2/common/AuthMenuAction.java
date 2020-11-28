package ex2.common;

import ex2.domain.exceptions.InvalidChoiceException;

/*
* Enum qui contient tous les actions du second menu pour WebAuth, le menu après authentification
* */
public enum AuthMenuAction implements ConsoleChoice {

    OPERATION(1, "Faire une opération"),
    KEY_STORE(2, "Visualiser la trousse de clés"),
    BACK(3, "Menu précédent"),
    QUIT(4, "Quitter");

    private final int entryNumber;
    private final String name;

    AuthMenuAction(int entryNumber, String name) {
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
    * Fonction pour obtenir la valeur de l'énum à partir du numéro choisis
    * */
    public static AuthMenuAction from(int number) {
        for (AuthMenuAction action : AuthMenuAction.values()) {
            if (action.getEntryNUmber() == number) {
                return action;
            }
        }
        throw new InvalidChoiceException(String.format("nothing correspond to choice: %d", number));
    }
}
