package ex2.domain.exceptions;

/*
* Exception pour un choix qui n'est pas valide. (choix = string lus de la console)
* */
public class InvalidChoiceException extends RuntimeException {
    public InvalidChoiceException(String message) {
        super(message);
    }
}
