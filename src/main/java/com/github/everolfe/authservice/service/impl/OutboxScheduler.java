package com.github.everolfe.authservice.service.impl;

import com.github.everolfe.authservice.dao.OutboxRepository;
import com.github.everolfe.authservice.entity.Outbox;
import com.github.everolfe.authservice.entity.OutboxStatus;
import java.util.List;
import lombok.RequiredArgsConstructor;
import net.javacrumbs.shedlock.spring.annotation.SchedulerLock;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class OutboxScheduler {

    private final OutboxRepository outboxRepository;
    private final OutboxProcessor outboxProcessor;

    @Scheduled(fixedDelay = 5000)
    @SchedulerLock(name = "outboxProcessor", lockAtMostFor = "30s")
    public void processOutboxMessages() {

        List<Outbox> pendingMessages =
                outboxRepository.findByStatus(OutboxStatus.PENDING);

        for (Outbox message : pendingMessages) {
            outboxProcessor.processSingleMessage(message.getId());
        }
    }
}