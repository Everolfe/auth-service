package com.github.everolfe.authservice.service.impl;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.everolfe.authservice.dao.OutboxRepository;
import com.github.everolfe.authservice.dao.UserCredentialRepository;
import com.github.everolfe.authservice.dto.CreateProfileDto;
import com.github.everolfe.authservice.entity.Outbox;
import com.github.everolfe.authservice.entity.OutboxStatus;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;

@Service
@RequiredArgsConstructor
@Slf4j
public class OutboxProcessor {

    private final OutboxRepository outboxRepository;
    private final UserCredentialRepository userCredentialRepository;
    private final ObjectMapper objectMapper;
    private final RestTemplate restTemplate;
    @Value("${app.userservice.url:http://localhost:8081/api/users/internal/register}")
    private String userServiceUrl;

    @Transactional
    public void processSingleMessage(UUID outboxId) {

        Outbox message = outboxRepository.findById(outboxId).orElse(null);

        if (message == null || message.getStatus() != OutboxStatus.PENDING) {
            return;
        }

        if (message.getRetryCount() >= 3) {
            rollbackUserCreation(message);
            return;
        }

        try {
            CreateProfileDto profileDto = objectMapper.readValue(
                    message.getPayload(),
                    CreateProfileDto.class
            );

            ResponseEntity<String> response = restTemplate.postForEntity(
                    userServiceUrl,
                    profileDto,
                    String.class
            );

            if (response.getStatusCode().is2xxSuccessful()) {
                message.setStatus(OutboxStatus.CREATED);
                outboxRepository.save(message);
                log.info("Outbox processed: {}", message.getId());
            } else {
                rollbackUserCreation(message);
            }

        } catch (HttpClientErrorException e) {

            HttpStatusCode status = e.getStatusCode();

            log.error("UserService error {} for user {}", status, message.getUserSub());

            if (status == HttpStatus.CONFLICT ||
                    status == HttpStatus.BAD_REQUEST ||
                    status == HttpStatus.UNPROCESSABLE_ENTITY) {

                rollbackUserCreation(message);
            } else {
                processFailedOutbox(message, e);
            }

        } catch (Exception e) {
            processFailedOutbox(message, e);
        }
    }

    private void processFailedOutbox(Outbox message, Exception e) {
        log.error("Failed to process outbox {} (attempt {})",
                message.getId(), message.getRetryCount() + 1);

        message.setRetryCount(message.getRetryCount() + 1);
        message.setLastError(e.getMessage());
        outboxRepository.save(message);
    }

    private void rollbackUserCreation(Outbox message) {
        log.warn("Rolling back user: {}", message.getUserSub());

        try {
            userCredentialRepository.deleteBySub(message.getUserSub());
            message.setStatus(OutboxStatus.ROLLBACK);
            outboxRepository.save(message);

            log.info("Rollback completed for: {}", message.getUserSub());

        } catch (Exception e) {
            log.error("CRITICAL: Rollback failed for {}", message.getUserSub(), e);

            message.setStatus(OutboxStatus.FAILED);
            outboxRepository.save(message);
        }
    }
}


