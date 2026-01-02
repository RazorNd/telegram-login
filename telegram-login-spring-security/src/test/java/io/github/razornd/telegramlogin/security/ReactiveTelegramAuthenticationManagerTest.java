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
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import reactor.core.publisher.Mono;

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

    TelegramAuthenticationValidator validator = mock(new Returns(ValidationResult.valid()));
    ReactiveTelegramAuthenticationManager manager = new ReactiveTelegramAuthenticationManager(validator);

    @Test
    void authenticate() {
        var authentication = new TelegramAuthenticationToken(TEST_USER, TEST_HASH);

        var actual = manager.authenticate(authentication).block();

        assertThat(actual)
                .isExactlyInstanceOf(TelegramAuthentication.class)
                .isEqualTo(new TelegramAuthentication(TEST_USER, Set.of()));
    }

    @Test
    void authenticateShouldValidateAuthentication() {
        var authentication = new TelegramAuthenticationToken(TEST_USER, TEST_HASH);

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

    @Test
    void authenticateWithCustomUserService() {
        var testPrincipal = mock(TelegramPrincipal.class);
        var customUserService = mock(ReactiveTelegramUserService.class);

        doReturn(Mono.just(testPrincipal)).when(customUserService).loadUser(any());

        manager.setUserService(customUserService);

        var actual = manager.authenticate(new TelegramAuthenticationToken(TEST_USER, TEST_HASH)).block();

        assertThat(actual)
                .extracting(Authentication::getPrincipal)
                .isSameAs(testPrincipal);
    }

    @Test
    void authenticateShouldUseAuthorityFromPrincipal() {
        var testPrincipal = mock(TelegramPrincipal.class);
        var customUserService = mock(ReactiveTelegramUserService.class);

        doReturn(Set.of(new SimpleGrantedAuthority("ROLE_ADMIN"))).when(testPrincipal).getAuthorities();
        doReturn(Mono.just(testPrincipal)).when(customUserService).loadUser(any());

        manager.setUserService(customUserService);

        var actual = manager.authenticate(new TelegramAuthenticationToken(TEST_USER, TEST_HASH)).block();

        assertThat(actual)
                .extracting(Authentication::getAuthorities)
                .asInstanceOf(InstanceOfAssertFactories.collection(GrantedAuthority.class))
                .extracting(GrantedAuthority::getAuthority)
                .containsExactly("ROLE_ADMIN");
    }
}
