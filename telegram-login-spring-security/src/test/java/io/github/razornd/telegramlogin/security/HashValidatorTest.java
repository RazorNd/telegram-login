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

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;

class HashValidatorTest {

    HashValidator hashValidator = new HashValidator("2326476206:3g9iZTSFL5Pw5jaVrRw6em9Va2IEKgOuUXkVf");

    @Test
    void validate() {
        var telegramUser = new TelegramUser(6787L,
                                            Instant.ofEpochSecond(1766499044L),
                                            "fc8fdb07f0cd97eed41f68fd7ee2e2b167d78be67bd55d657fa334b8960bf7b5",
                                            "Lesia",
                                            "Thane",
                                            "cora5",
                                            "https://t.me/i/userpic/320/hamptonkfaur7.uqh.jpg");

        var actual = hashValidator.validate(new TelegramAuthenticationToken(telegramUser));

        assertThat(actual).isEqualTo(ValidationResult.valid());
    }

    @Test
    void validateShouldCorrectWorkWithNullFields() {
        var telegramUser = new TelegramUser(567880L,
                                            Instant.parse("2023-05-29T15:54:48Z"),
                                            "31788de82422ffafed19d359888f2df0b301155cd030e293c701eeeb39d3d083",
                                            null,
                                            null,
                                            "antwinew8yd",
                                            null);

        var actual = hashValidator.validate(new TelegramAuthenticationToken(telegramUser));

        assertThat(actual).isEqualTo(ValidationResult.valid());
    }

    @Test
    void validateShouldReturnIncorrectResultForWrongHash() {
        var telegramUser = new TelegramUser(14984267L,
                                            Instant.parse("2025-12-23T21:52:13Z"),
                                            "31788de82422ffafed19d359888f2df0b301155cd030e293c701eeeb39d3d083",
                                            null,
                                            null,
                                            "kyndraryu",
                                            null);

        var actual = hashValidator.validate(new TelegramAuthenticationToken(telegramUser));

        assertThat(actual).isEqualTo(ValidationResult.invalid("Invalid hash"));
    }

    @Test
    void validateShouldReturnIncorrectResultOnNotHexHash() {
        var telegramUser = new TelegramUser(24968L,
                                            Instant.parse("2025-12-23T21:52:13Z"),
                                            "not-a-hex-hash",
                                            null,
                                            null,
                                            "kyndraryu",
                                            null);

        var actual = hashValidator.validate(new TelegramAuthenticationToken(telegramUser));

        assertThat(actual).isEqualTo(ValidationResult.invalid("Invalid hash format"));
    }
}
