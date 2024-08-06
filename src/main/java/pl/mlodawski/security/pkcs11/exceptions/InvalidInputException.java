package pl.mlodawski.security.pkcs11.exceptions;

/**
 * {@code InvalidInputException} is an exception class that represents an invalid input.
 * It is a subclass of {@link IllegalArgumentException}.
 *
 * This exception is typically thrown when an input value is not valid for a specific operation
 * or when a method is called with incorrect arguments.
 *
 * @see IllegalArgumentException
 */
public class InvalidInputException extends IllegalArgumentException {
    public InvalidInputException(String message) {
        super(message);
    }
}