package ex2.domain.exceptions;

/*
* Classe pour les exceptions où on demande à une entité de protocole d'exécuter une étape qu'il ne peut pas exécuter
* */
public class InvalidProtocolStepException extends RuntimeException {
    public InvalidProtocolStepException(String message) {
        super(InvalidProtocolStepException.class.getName() + System.lineSeparator() + message);
    }
}
