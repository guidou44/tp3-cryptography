package ex2.common;

import ex2.domain.exceptions.InvalidChoiceException;

public enum AuthMenuAction implements ConsoleChoice {

    OPERATION(1, "Faire une opération"),
    KEY_STORE(2, "Visualiser la trousse de clés"),
    BACK(3, "Menu précédent"),
    QUIT(4, "Quitter");

    private int entryNumber;
    private String name;

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

    public static AuthMenuAction from(int number) {
        for (AuthMenuAction action : AuthMenuAction.values()) {
            if (action.getEntryNUmber() == number) {
                return action;
            }
        }
        throw new InvalidChoiceException(String.format("nothing correspond to choice: %d", number));
    }
}
