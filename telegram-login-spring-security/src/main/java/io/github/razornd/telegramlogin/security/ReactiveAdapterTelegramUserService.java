/*
 * Copyright 2026 Daniil Razorenov
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */

package io.github.razornd.telegramlogin.security;

import reactor.core.publisher.Mono;

/**
 * Adapter that wraps a synchronous {@link TelegramUserService} to be used as a {@link ReactiveTelegramUserService}.
 *
 * @author Daniil Razorenov
 */
public class ReactiveAdapterTelegramUserService implements ReactiveTelegramUserService {

    private final TelegramUserService delegate;

    /**
     * Creates a new {@link ReactiveAdapterTelegramUserService} that delegates to the given {@link TelegramUserService}.
     *
     * @param userService the synchronous user service to delegate to
     */
    public ReactiveAdapterTelegramUserService(TelegramUserService userService) {
        this.delegate = userService;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Mono<TelegramPrincipal> loadUser(TelegramUser user) {
        return Mono.defer(() -> Mono.just(delegate.loadUser(user)));
    }
}
