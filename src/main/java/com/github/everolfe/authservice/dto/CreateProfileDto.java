package com.github.everolfe.authservice.dto;

import java.time.LocalDate;
import java.util.UUID;
import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class CreateProfileDto {
    private UUID sub;
    private String name;
    private String surname;
    private LocalDate birthDate;
    private String email;
}
