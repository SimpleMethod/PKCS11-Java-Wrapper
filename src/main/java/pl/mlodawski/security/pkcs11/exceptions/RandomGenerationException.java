package pl.mlodawski.security.pkcs11.exceptions;

/**
 * Exception thrown when hardware random number generation fails.
 */
public class RandomGenerationException extends RuntimeException {
    public RandomGenerationException(String message, Throwable cause) {
        super(message, cause);
    }
}
