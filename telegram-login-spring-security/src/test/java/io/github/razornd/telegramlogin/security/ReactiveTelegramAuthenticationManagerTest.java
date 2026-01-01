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

import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;

import java.time.Instant;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

class ReactiveTelegramAuthenticationManagerTest {

    private static final TelegramUser TEST_USER = new TelegramUser(38645L,
                                                                   Instant.parse("2019-08-02T01:28:23Z"),
                                                                   "Davi",
                                                                   null,
                                                                   null,
                                                                   null);
    private static final String TEST_HASH = "7aj8wLLb9OljS86ZakF2s4OdlxJ9YeivCH2iOyxsi3hVX";

    TelegramAuthenticationValidator validator = mock();
    ReactiveTelegramAuthenticationManager manager = new ReactiveTelegramAuthenticationManager(validator);

    @Test
    void authenticate() {
        var authentication = new TelegramAuthenticationToken(TEST_USER, TEST_HASH);

        doReturn(ValidationResult.valid()).when(validator).validate(any());

        var actual = manager.authenticate(authentication).block();

        assertThat(actual)
                .isExactlyInstanceOf(TelegramAuthentication.class)
                .isEqualTo(new TelegramAuthentication(TEST_USER, Set.of()));
    }

    @Test
    void authenticateShouldValidateAuthentication() {
        var authentication = new TelegramAuthenticationToken(TEST_USER, TEST_HASH);

        doReturn(ValidationResult.valid()).when(validator).validate(any());

        manager.authenticate(authentication).block();

        verify(validator).validate(same(authentication));
    }

    @Test
    void authenticateShouldReturnInvalidResultOnFailedValidation() {
        var authentication = new TelegramAuthenticationToken(TEST_USER, TEST_HASH);

        doReturn(ValidationResult.invalid("Invalid hash")).when(validator).validate(any());

        assertThatThrownBy(() -> manager.authenticate(authentication).block())
                .isExactlyInstanceOf(BadCredentialsException.class)
                .hasMessage("Invalid hash");
    }

    @Test
    void authenticateShouldReturnEmptyMonoOnUnsupportedAuthToken() {
        var authentication = UsernamePasswordAuthenticationToken.unauthenticated("test-user", "test-password");

        var actual = manager.authenticate(authentication).block();

        assertThat(actual).isNull();
    }
}
