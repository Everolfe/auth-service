package com.github.everolfe.authservice.exception;

import com.github.everolfe.authservice.dto.GetErrorDto;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.ExpiredJwtException;
import java.time.LocalDateTime;
import java.util.stream.Collectors;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.context.request.WebRequest;

@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(DataIntegrityViolationException.class)
    public ResponseEntity<GetErrorDto> handleDataIntegrityViolation(
            DataIntegrityViolationException ex, WebRequest request) {
        return buildErrorResponse(
                "A resource with these details already exists or violates data constraints.",
                HttpStatus.CONFLICT,
                request
        );
    }

    @ExceptionHandler({ExpiredJwtException.class, JwtException.class})
    public ResponseEntity<GetErrorDto> handleJwtErrors(
            JwtException ex, WebRequest request) {

        return buildErrorResponse(
                "JWT Token is expired or invalid: " + ex.getMessage(),
                HttpStatus.UNAUTHORIZED, request
        );
    }


    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<GetErrorDto> handleValidationExceptions(
            MethodArgumentNotValidException ex, WebRequest request) {

        String errorMessage = ex.getBindingResult().getFieldErrors().stream()
                .map(error -> error.getField() + ": " + error.getDefaultMessage())
                .collect(Collectors.joining("; "));

        return buildErrorResponse(
                errorMessage,
                HttpStatus.BAD_REQUEST,
                request
        );
    }

    @ExceptionHandler(UsernameNotFoundException.class)
    public ResponseEntity<GetErrorDto> handleUsernameNotFound(
            UsernameNotFoundException ex, WebRequest request) {

        return buildErrorResponse(
                ex.getMessage(),
                HttpStatus.NOT_FOUND, request
        );
    }

    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<GetErrorDto> handleMalformedJson(
            HttpMessageNotReadableException ex, WebRequest request) {

        return buildErrorResponse(
                "Invalid request body: JSON is malformed.",
                HttpStatus.BAD_REQUEST,
                request
        );
    }

    @ExceptionHandler(AuthenticationException.class)
    public ResponseEntity<GetErrorDto> handleAuthenticationException(
            AuthenticationException ex, WebRequest request) {

        return buildErrorResponse(
                "Authentication failed: " + ex.getMessage(),
                HttpStatus.UNAUTHORIZED,
                request
        );
    }

    @ExceptionHandler(BadCredentialsException.class)
    public ResponseEntity<GetErrorDto> handleBadCredentials(
            BadCredentialsException ex, WebRequest request) {

        return buildErrorResponse(
                "Invalid username or password",
                HttpStatus.UNAUTHORIZED, request
        );
    }

    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<GetErrorDto> handleAccessDeniedException(
            AccessDeniedException ex, WebRequest request) {

        return buildErrorResponse(
                "Access Denied: You do not have permission to access this resource.",
                HttpStatus.FORBIDDEN,
                request
        );
    }

    private ResponseEntity<GetErrorDto> buildErrorResponse(
            String message, HttpStatus status, WebRequest request) {

        GetErrorDto errorDto = new GetErrorDto(
                LocalDateTime.now(),
                status.value(),
                status.getReasonPhrase(),
                message,
                request.getDescription(false).replace("uri=", "")
        );

        return new ResponseEntity<>(errorDto, status);
    }
}
