package ex2.common;

import ex2.domain.exceptions.InvalidChoiceException;

public enum FirstMenuAction implements ConsoleInteraction {

    REGISTER(1, "Enregistrer un nouveau compte"),
    AUTHENTICATE(2, "Authentification"),
    BACK(3, "Menu précédent"),
    QUIT(4, "Quitter");

    private int entryNumber;
    private String name;

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

    public static FirstMenuAction from(int number) {
        for (FirstMenuAction action : FirstMenuAction.values()) {
            if (action.getEntryNUmber() == number) {
                return action;
            }
        }
        throw new InvalidChoiceException(String.format("nothing correspond to choice: %d", number));
    }
}
