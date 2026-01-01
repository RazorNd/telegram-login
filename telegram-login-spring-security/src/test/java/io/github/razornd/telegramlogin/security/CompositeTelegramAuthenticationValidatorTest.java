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

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;

class CompositeTelegramAuthenticationValidatorTest {

    @Test
    void shouldReturnValidWhenNoValidators() {
        var composite = new CompositeTelegramAuthenticationValidator(List.of());
        var token = mock(TelegramAuthenticationToken.class);

        assertThat(composite.validate(token)).isEqualTo(ValidationResult.valid());
    }

    @Test
    void shouldReturnValidWhenAllValidatorsReturnValid() {
        var v1 = mock(TelegramAuthenticationValidator.class);
        var v2 = mock(TelegramAuthenticationValidator.class);
        var token = mock(TelegramAuthenticationToken.class);

        doReturn(ValidationResult.valid()).when(v1).validate(token);
        doReturn(ValidationResult.valid()).when(v2).validate(token);

        var composite = new CompositeTelegramAuthenticationValidator(List.of(v1, v2));

        assertThat(composite.validate(token)).isEqualTo(ValidationResult.valid());
    }

    @Test
    void shouldReturnInvalidWhenOneValidatorReturnsInvalid() {
        var v1 = mock(TelegramAuthenticationValidator.class);
        var v2 = mock(TelegramAuthenticationValidator.class);
        var token = mock(TelegramAuthenticationToken.class);

        doReturn(ValidationResult.valid()).when(v1).validate(token);
        doReturn(ValidationResult.invalid("reason 2")).when(v2).validate(token);

        var composite = new CompositeTelegramAuthenticationValidator(List.of(v1, v2));

        assertThat(composite.validate(token)).isEqualTo(ValidationResult.invalid("reason 2"));
    }

    @Test
    void shouldReturnCombinedInvalidWhenMultipleValidatorsReturnInvalid() {
        var v1 = mock(TelegramAuthenticationValidator.class);
        var v2 = mock(TelegramAuthenticationValidator.class);
        var token = mock(TelegramAuthenticationToken.class);

        doReturn(ValidationResult.invalid("reason 1")).when(v1).validate(token);
        doReturn(ValidationResult.invalid("reason 2")).when(v2).validate(token);

        var composite = new CompositeTelegramAuthenticationValidator(List.of(v1, v2));

        assertThat(composite.validate(token)).isEqualTo(ValidationResult.invalid("reason 1, reason 2"));
    }
}
