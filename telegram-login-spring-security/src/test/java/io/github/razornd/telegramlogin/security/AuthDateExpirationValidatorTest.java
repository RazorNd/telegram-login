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

import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;

import static org.assertj.core.api.Assertions.assertThat;

class AuthDateExpirationValidatorTest {

    private static final Instant AUTH_DATE = Instant.parse("2025-12-24T11:25:42Z");
    private static final String AUTH_HASH = "r4iRFivc55GotcYRPrYh7j7LmpChKFCzgKFMtKtHlc";

    private static final TelegramUser TEST_TELEGRAM_USER = new TelegramUser(93248L,
                                                                            AUTH_DATE,
                                                                            null,
                                                                            null,
                                                                            null,
                                                                            null);

    AuthDateExpirationValidator validator = new AuthDateExpirationValidator();

    @Test
    void validate() {
        validator.setClock(Clock.fixed(AUTH_DATE.plusSeconds(20), ZoneOffset.UTC));

        var actual = validator.validate(new TelegramAuthenticationToken(TEST_TELEGRAM_USER, AUTH_HASH));

        assertThat(actual).isEqualTo(ValidationResult.valid());
    }

    @Test
    void validateShouldReturnInvalidResultWhenAuthDateIsExpired() {
        validator.setClock(Clock.fixed(AUTH_DATE.plus(Duration.ofMinutes(2)), ZoneOffset.UTC));
        validator.setExpirationDuration(Duration.ofMinutes(1));

        var actual = validator.validate(new TelegramAuthenticationToken(TEST_TELEGRAM_USER, AUTH_HASH));

        assertThat(actual).isEqualTo(ValidationResult.invalid("auth_date expired"));
    }
}
