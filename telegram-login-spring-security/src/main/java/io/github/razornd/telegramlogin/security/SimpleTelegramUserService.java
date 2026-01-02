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

/**
 * Simple implementation of {@link TelegramUserService} that returns the provided {@link TelegramUser} as the principal.
 *
 * <p>This implementation does not perform any additional user loading or data enrichment.
 *
 * @author Daniil Razorenov
 */
public class SimpleTelegramUserService implements TelegramUserService {
    /**
     * {@inheritDoc}
     */
    @Override
    public TelegramPrincipal loadUser(TelegramUser user) {
        return user;
    }
}
