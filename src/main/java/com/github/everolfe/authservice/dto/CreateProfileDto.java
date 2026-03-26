package com.github.everolfe.authservice.dto;

import java.time.LocalDate;
import java.util.UUID;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class CreateProfileDto {
    private UUID sub;
    private String name;
    private String surname;
    private LocalDate birthDate;
    private String email;
}
