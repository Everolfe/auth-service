package com.github.everolfe.authservice.config.listener;


import com.github.everolfe.authservice.config.event.OutboxCreatedEvent;
import com.github.everolfe.authservice.service.impl.OutboxProcessor;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import org.springframework.transaction.event.TransactionPhase;
import org.springframework.transaction.event.TransactionalEventListener;

import java.util.concurrent.CompletableFuture;

@Component
@RequiredArgsConstructor
public class OutboxEventListener {

    private final OutboxProcessor outboxProcessor;

    @TransactionalEventListener(phase = TransactionPhase.AFTER_COMMIT)
    public void handleOutboxCreated(OutboxCreatedEvent event) {
        CompletableFuture.runAsync(() -> {
            outboxProcessor.processSingleMessage(event.getOutboxId());
        });
    }
}
