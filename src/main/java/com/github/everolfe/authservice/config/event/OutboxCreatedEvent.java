package com.github.everolfe.authservice.config.event;

import java.util.UUID;
import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Getter
@RequiredArgsConstructor
public class OutboxCreatedEvent {
    private final UUID outboxId;
}
