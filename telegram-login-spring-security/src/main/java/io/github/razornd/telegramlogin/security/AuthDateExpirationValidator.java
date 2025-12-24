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

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;

public class AuthDateExpirationValidator implements TelegramAuthenticationValidator {

    private Duration expirationDuration = Duration.ofHours(24);
    private Clock clock = Clock.systemUTC();

    @Override
    public ValidationResult validate(TelegramAuthenticationToken token) {
        var authenticationDate = token.getPrincipal().authDate();

        var now = Instant.now(clock);

        if (authenticationDate.isBefore(now.minus(expirationDuration))) {
            return ValidationResult.invalid("auth_date expired");
        }

        return ValidationResult.valid();
    }

    public void setExpirationDuration(Duration expirationDuration) {
        this.expirationDuration = expirationDuration;
    }

    public void setClock(Clock clock) {
        this.clock = clock;
    }
}
