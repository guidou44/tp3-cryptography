package ex2.domain.exceptions;

public class InvalidChoiceException extends RuntimeException {
    public InvalidChoiceException(String message) {
        super(message);
    }
}
