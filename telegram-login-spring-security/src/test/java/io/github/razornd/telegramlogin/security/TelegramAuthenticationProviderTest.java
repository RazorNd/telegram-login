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

import org.assertj.core.api.InstanceOfAssertFactories;
import org.junit.jupiter.api.Test;
import org.mockito.internal.stubbing.answers.Returns;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.FactorGrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.time.Instant;
import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

class TelegramAuthenticationProviderTest {

    private static final String TEST_USER_HASH = "F192pHQTGO0Rc2hv8ko1";
    private static final TelegramUser TEST_USER = new TelegramUser(5114845L,
                                                                   Instant.parse("2023-05-29T15:54:48Z"),
                                                                   null,
                                                                   null,
                                                                   null,
                                                                   null);

    TelegramAuthenticationValidator validator = mock(new Returns(ValidationResult.valid()));
    TelegramAuthenticationProvider provider = new TelegramAuthenticationProvider(validator);

    @Test
    void authenticate() {
        var testAuthToken = new TestAuthenticationToken(TEST_USER, TEST_USER_HASH);
        var factorAuthority = FactorGrantedAuthority.fromFactor(TelegramAuthenticationProvider.AUTHENTICATION_FACTOR);

        var actual = provider.authenticate(testAuthToken);

        assertThat(actual)
                .usingRecursiveComparison()
                .ignoringFieldsOfTypes(Instant.class)
                .isEqualTo(new TelegramAuthentication(TEST_USER, List.of(factorAuthority)));
    }

    @Test
    void authenticateShouldValidateAuthentication() {
        var testAuthToken = new TestAuthenticationToken(TEST_USER, TEST_USER_HASH);

        provider.authenticate(testAuthToken);

        verify(validator).validate(testAuthToken);
    }

    @Test
    void authenticateShouldThrowBadRequestOnFailedValidation() {
        doReturn(ValidationResult.invalid("test reason")).when(validator).validate(any());

        var testAuthToken = new TestAuthenticationToken(TEST_USER, TEST_USER_HASH);

        assertThatThrownBy(() -> provider.authenticate(testAuthToken))
                .isInstanceOf(BadCredentialsException.class)
                .hasMessage("test reason");
    }

    @Test
    void authenticateWithCustomUserService() {
        var customUserService = mock(TelegramUserService.class);

        var principal = mock(TelegramPrincipal.class);
        doReturn(principal).when(customUserService).loadUser(any());

        provider.setUserService(customUserService);

        var testAuthToken = new TelegramAuthenticationToken(TEST_USER, TEST_USER_HASH);
        var actual = provider.authenticate(testAuthToken);

        assertThat(actual).extracting(TelegramAuthentication::getPrincipal).isSameAs(principal);
        verify(customUserService).loadUser(TEST_USER);
    }

    @Test
    void authenticateShouldUseAuthoritiesFromPrincipal() {
        var principal = mock(TelegramPrincipal.class);
        var customUserService = mock(TelegramUserService.class);

        doReturn(Set.of(new SimpleGrantedAuthority("ROLE_ADMIN"))).when(principal).getAuthorities();
        doReturn(principal).when(customUserService).loadUser(any());

        provider.setUserService(customUserService);

        var authenticationToken = new TelegramAuthenticationToken(TEST_USER, TEST_USER_HASH);

        var actual = provider.authenticate(authenticationToken);

        assertThat(actual)
                .extracting(TelegramAuthentication::getAuthorities)
                .asInstanceOf(InstanceOfAssertFactories.collection(GrantedAuthority.class))
                .extracting(GrantedAuthority::getAuthority)
                .containsExactlyInAnyOrder("ROLE_ADMIN", "FACTOR_TELEGRAM");

    }

    @Test
    void supports() {
        var actual = provider.supports(TestAuthenticationToken.class);

        assertThat(actual).isTrue();
    }

    static class TestAuthenticationToken extends TelegramAuthenticationToken {
        TestAuthenticationToken(TelegramUser principal, String hash) {
            super(principal, hash);
        }
    }
}
