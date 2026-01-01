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
 * Represents the principal entity authenticated using the Telegram Login Widget.
 * This interface defines a contract for retrieving the Telegram user's unique identifier.
 */
public interface TelegramPrincipal {

    /**
     * Retrieves the unique identifier of the authenticated Telegram user.
     *
     * @return the Telegram user's unique identifier as a long value
     */
    long getTelegramId();

}
