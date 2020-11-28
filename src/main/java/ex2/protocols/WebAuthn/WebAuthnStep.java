package ex2.protocols.WebAuthn;


import ex2.protocols.base.IProtocolStep;

/*
 * Énumération de tous les étapes de WebAuthn
 * */
public enum WebAuthnStep implements IProtocolStep {

    E1("E1. C → S : "),
    E2("E2. S → C : "),
    E3("E3. C → S : "),
    E4("E4. s → C : "),

    A1("A1. C → S : "),
    A2("A2. S → C : "),
    A3("A3. C → S : "),
    A4("A4. s → C : "),

    T1("T1. C → S : "),
    T2("T2. S → C : "),
    T3("T3. C → S : "),
    T4("T4. s → C : "),
    END("EXCHANGE DONE");

    private final String prettyRepresentation;//représentation d'une étape à l'écran

    WebAuthnStep(String prettyRepresentation) {
        this.prettyRepresentation = prettyRepresentation;
    }

    public String toStringWithMessage(String message) {
        return prettyRepresentation + message + System.lineSeparator();
    }
}
