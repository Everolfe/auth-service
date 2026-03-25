package com.github.everolfe.authservice.dto.auth;

import com.github.everolfe.authservice.dto.CreateProfileDto;
import java.time.LocalDate;
import java.util.UUID;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
public class CreateAuthDto {
    private String email;
    private String password;
    private String name;
    private String surname;
    private LocalDate birthDate;

    public CreateProfileDto toProfileDto(UUID sub) {
        return CreateProfileDto.builder()
                .sub(sub)
                .email(this.email)
                .name(this.name)
                .surname(this.surname)
                .birthDate(this.birthDate)
                .build();
    }
}

