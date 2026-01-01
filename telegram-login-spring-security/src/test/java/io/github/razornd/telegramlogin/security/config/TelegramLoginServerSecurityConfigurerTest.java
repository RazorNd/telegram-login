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

package io.github.razornd.telegramlogin.security.config;

import io.github.razornd.telegramlogin.security.HashValidator;
import io.github.razornd.telegramlogin.security.TelegramAuthenticationValidator;
import io.github.razornd.telegramlogin.security.TestHashUtils;
import io.github.razornd.telegramlogin.security.ValidationResult;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.authentication.ServerAuthenticationConverter;
import org.springframework.security.web.server.authentication.ServerAuthenticationFailureHandler;
import org.springframework.security.web.server.authentication.ServerAuthenticationSuccessHandler;
import org.springframework.security.web.server.context.ServerSecurityContextRepository;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import java.util.Map;

import static io.github.razornd.telegramlogin.security.config.TelegramLoginServerSecurityConfigurer.telegramLogin;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

class TelegramLoginServerSecurityConfigurerTest {

    private static final String BOT_TOKEN = "token";

    @Test
    void shouldAuthenticateWithDefaultUrl() {
        String date = TestHashUtils.currentDate();
        String hash = TestHashUtils.calcHash(BOT_TOKEN, Map.of("id", "1",
                                                               "first_name", "John",
                                                               "username", "john_doe",
                                                               "auth_date", date));

        WebTestClient client = createClient(t -> t.botToken(BOT_TOKEN));

        client.get()
              .uri("/login/telegram?id=1&first_name=John&username=john_doe&auth_date=" + date + "&hash=" + hash)
              .exchange()
              .expectStatus().is3xxRedirection();
    }

    @Test
    void shouldAuthenticateWithCustomUrl() {
        String date = TestHashUtils.currentDate();
        String hash = TestHashUtils.calcHash(BOT_TOKEN, Map.of("id", "1",
                                                               "first_name", "John",
                                                               "username", "john_doe",
                                                               "auth_date", date));

        WebTestClient client = createClient(t -> t.botToken(BOT_TOKEN).loginProcessingUrl("/custom/login"));

        client.get()
              .uri("/custom/login?id=1&first_name=John&username=john_doe&auth_date=" + date + "&hash=" + hash)
              .exchange()
              .expectStatus().is3xxRedirection();
    }

    @Test
    void shouldFailAuthenticationWithInvalidHash() {
        WebTestClient client = createClient(t -> t.botToken(BOT_TOKEN));

        client.get()
              .uri("/login/telegram?id=1&first_name=John&username=john_doe&auth_date=1&hash=invalid")
              .exchange()
              .expectStatus().isUnauthorized();
    }

    @Test
    void shouldInvokeSuccessHandler() {
        ServerAuthenticationSuccessHandler successHandler = mock(ServerAuthenticationSuccessHandler.class);
        doReturn(Mono.empty()).when(successHandler).onAuthenticationSuccess(any(), any());

        String date = TestHashUtils.currentDate();
        String hash = TestHashUtils.calcHash(BOT_TOKEN, Map.of("id", "1",
                                                               "first_name", "John",
                                                               "username", "john_doe",
                                                               "auth_date", date));

        WebTestClient client = createClient(t -> t.botToken(BOT_TOKEN)
                                                  .loginProcessingUrl("/success/login")
                                                  .successHandler(successHandler)
                                                  .authenticationManager(authentication -> Mono.just(mock(Authentication.class)))
        );

        client.get()
              .uri("/success/login?id=1&first_name=John&username=john_doe&auth_date=" + date + "&hash=" + hash)
              .exchange();

        verify(successHandler).onAuthenticationSuccess(any(), any());
    }

    @Test
    void shouldInvokeFailureHandler() {
        ServerAuthenticationFailureHandler failureHandler = mock(ServerAuthenticationFailureHandler.class);
        doReturn(Mono.empty()).when(failureHandler).onAuthenticationFailure(any(), any());

        WebTestClient client = createClient(t -> t.botToken("token")
                                                  .loginProcessingUrl("/failure/login")
                                                  .failureHandler(failureHandler)
        );

        client.get()
              .uri("/failure/login?id=1&first_name=John&username=john_doe&auth_date=1&hash=invalid")
              .exchange();

        verify(failureHandler).onAuthenticationFailure(any(), any());
    }

    @Test
    void shouldInvokeCustomValidator() {
        TelegramAuthenticationValidator customValidator = mock(TelegramAuthenticationValidator.class);
        doReturn(ValidationResult.invalid("test")).when(customValidator).validate(any());

        WebTestClient client = createClient(t -> t.botToken("token")
                                                  .loginProcessingUrl("/validator/login")
                                                  .validators(customValidator)
        );

        client.get()
              .uri("/validator/login?id=1&first_name=John&username=john_doe&auth_date=1&hash=invalid")
              .exchange()
              .expectStatus().isUnauthorized();

        verify(customValidator).validate(any());
    }

    @Test
    void shouldInvokeCustomAuthenticationManager() {
        ReactiveAuthenticationManager customAuthenticationManager = mock(ReactiveAuthenticationManager.class);
        doReturn(Mono.just(mock(Authentication.class))).when(customAuthenticationManager).authenticate(any());

        WebTestClient client = createClient(t -> t.botToken("token")
                                                  .loginProcessingUrl("/manager/login")
                                                  .authenticationManager(customAuthenticationManager)
        );

        client.get()
              .uri("/manager/login?id=1&first_name=John&username=john_doe&auth_date=1&hash=invalid")
              .exchange();

        verify(customAuthenticationManager).authenticate(any());
    }

    @Test
    void shouldInvokeCustomAuthenticationConverter() {
        ServerAuthenticationConverter customAuthenticationConverter = mock(ServerAuthenticationConverter.class);
        doReturn(Mono.empty()).when(customAuthenticationConverter).convert(any());

        WebTestClient client = createClient(t -> t.botToken("token")
                                                  .loginProcessingUrl("/converter/login")
                                                  .authenticationConverter(customAuthenticationConverter)
        );

        client.get()
              .uri("/converter/login?id=1&first_name=John&username=john_doe&auth_date=1&hash=invalid")
              .exchange();

        verify(customAuthenticationConverter).convert(any());
    }

    @Test
    void shouldInvokeCustomSecurityContextRepository() {
        ServerSecurityContextRepository customSecurityContextRepository = mock(ServerSecurityContextRepository.class);
        doReturn(Mono.empty()).when(customSecurityContextRepository).load(any());
        doReturn(Mono.empty()).when(customSecurityContextRepository).save(any(), any());

        WebTestClient client = createClient(t -> t.botToken("token")
                                                  .loginProcessingUrl("/repository/login")
                                                  .securityContextRepository(customSecurityContextRepository)
                                                  .authenticationManager(authentication -> Mono.just(mock(Authentication.class)))
        );

        client.get()
              .uri("/repository/login?id=1&first_name=John&username=john_doe&auth_date=1&hash=invalid")
              .exchange();

        verify(customSecurityContextRepository).save(any(), any());
    }

    @Test
    void shouldInvokeCustomHashValidator() {
        HashValidator customHashValidator = mock(HashValidator.class);
        doReturn(ValidationResult.invalid("test")).when(customHashValidator).validate(any());

        WebTestClient client = createClient(t -> t.loginProcessingUrl("/hash/login")
                                                  .hashValidator(customHashValidator));

        client.get()
              .uri("/hash/login?id=1&first_name=John&username=john_doe&auth_date=1&hash=invalid")
              .exchange();

        verify(customHashValidator).validate(any());
    }

    private WebTestClient createClient(java.util.function.Consumer<TelegramLoginServerSecurityConfigurer> customizer) {
        return new WebTestClientBuilder(telegramLogin(ServerHttpSecurity.http(), customizer).build()).build();
    }

    private record WebTestClientBuilder(SecurityWebFilterChain filterChain) {

        public WebTestClient build() {
                return WebTestClient.bindToWebHandler(exchange -> filterChain.getWebFilters()
                                                                             .collectList()
                                                                             .flatMap(filters -> {
                                                                                 WebFilterChain chain = e -> Mono.empty();
                                                                                 for (int i = filters.size() - 1; i >= 0;
                                                                                      i--) {
                                                                                     WebFilter filter = filters.get(
                                                                                             i);
                                                                                     WebFilterChain finalChain = chain;
                                                                                     chain = e -> filter.filter(e,
                                                                                                                finalChain);
                                                                                 }
                                                                                 return chain.filter(exchange);
                                                                             }))
                                    .build();
            }
        }
}
