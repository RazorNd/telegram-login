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

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;

/**
 * A {@link TelegramAuthenticationValidator} that checks if the Telegram authentication date has expired.
 *
 * <p>By default, the expiration duration is set to 24 hours.
 *
 * @author Daniil Razorenov
 * @see TelegramUser#authDate()
 */
public class AuthDateExpirationValidator implements TelegramAuthenticationValidator {

    private Duration expirationDuration = Duration.ofHours(24);
    private Clock clock = Clock.systemUTC();

    /**
     * Validates that the authentication date in the given token is not older than
     * the configured {@link #expirationDuration}.
     * @param token the token to validate
     * @return {@link ValidationResult#valid()} if not expired, or {@link ValidationResult#invalid(String)} otherwise
     */
    @Override
    public ValidationResult validate(TelegramAuthenticationToken token) {
        var authenticationDate = token.getPrincipal().authDate();

        var now = Instant.now(clock);

        if (authenticationDate.isBefore(now.minus(expirationDuration))) {
            return ValidationResult.invalid("auth_date expired");
        }

        return ValidationResult.valid();
    }

    /**
     * Sets the duration after which the authentication date is considered expired.
     * @param expirationDuration the expiration duration
     */
    public void setExpirationDuration(Duration expirationDuration) {
        this.expirationDuration = expirationDuration;
    }

    /**
     * Sets the {@link Clock} to use for determining the current time.
     * @param clock the clock to use
     */
    public void setClock(Clock clock) {
        this.clock = clock;
    }
}
