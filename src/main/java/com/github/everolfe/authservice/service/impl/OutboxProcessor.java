package com.github.everolfe.authservice.service.impl;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.everolfe.authservice.dao.OutboxRepository;
import com.github.everolfe.authservice.dto.CreateProfileDto;
import com.github.everolfe.authservice.entity.Outbox;
import com.github.everolfe.authservice.entity.OutboxStatus;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.javacrumbs.shedlock.spring.annotation.SchedulerLock;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.client.RestTemplate;
import java.util.List;

@Slf4j
@Service
@RequiredArgsConstructor
public class OutboxProcessor {

    private final OutboxRepository outboxRepository;
    private final RestTemplate restTemplate;
    private final ObjectMapper objectMapper;

    @Value("${app.userservice.url:http://localhost:8081/api/users/internal/register}")
    private String userServiceUrl;

    @Scheduled(fixedDelay = 5000)
    @SchedulerLock(name = "outboxProcessor", lockAtMostFor = "30s")
    @Transactional
    public void processOutboxMessages() {
        List<Outbox> pendingMessages = outboxRepository.findByStatus(OutboxStatus.PENDING);

        for (Outbox message : pendingMessages) {
            try {
                CreateProfileDto profileDto = objectMapper.readValue(
                        message.getPayload(),
                        CreateProfileDto.class
                );

                restTemplate.postForObject(userServiceUrl, profileDto, String.class);

                outboxRepository.deleteById(message.getId());
                log.info("Outbox message processed: {}", message.getId());

            } catch (Exception e) {
                log.error("Failed to process outbox message: {}", message.getId(), e);
            }
        }
    }
}