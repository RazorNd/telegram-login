/*
 * Copyright 2025 Daniil Razorenov
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
 * Strategy interface for validating Telegram authentication tokens.
 *
 * <p>Implementations are responsible for checking various aspects of the authentication
 * data, such as hash integrity, data freshness, etc.
 *
 * @author Daniil Razorenov
 * @see TelegramAuthenticationToken
 * @see ValidationResult
 */
public interface TelegramAuthenticationValidator {

    /**
     * Validates the given {@link TelegramAuthenticationToken}.
     * @param token the token to validate
     * @return the result of the validation
     */
    ValidationResult validate(TelegramAuthenticationToken token);
}
