package ex2.protocols.HttpDigest;

import ex2.protocols.base.IProtocolStep;

public enum HttpDigestStep implements IProtocolStep {

    E1("E1. C → S : "),
    E2("E2. S → C : "),

    A1("A1. C → S : "),
    A2("A2. S → C : "),
    A3("A3. C → S : "),
    A4("A4. s → C : "),

    END("EXCHANGE DONE");

    private final String prettyRepresentation;//représentation d'une étape à l'écran

    HttpDigestStep(String prettyRepresentation) {
        this.prettyRepresentation = prettyRepresentation;
    }

    @Override
    public String toStringWithMessage(String message) {
        return prettyRepresentation + message + System.lineSeparator();
    }
}
