package ex2.domain.exceptions;

public class InvalidUserException extends RuntimeException {
    public InvalidUserException(String message) {
        super(InvalidUserException.class.getName() + System.lineSeparator() + message);
    }

    @Override
    public String toString() {
        return "Provided user does not exists";
    }
}
