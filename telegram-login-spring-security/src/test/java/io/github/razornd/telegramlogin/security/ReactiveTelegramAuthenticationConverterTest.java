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
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.util.MultiValueMap;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class ReactiveTelegramAuthenticationConverterTest {

    ReactiveTelegramAuthenticationConverter converter = new ReactiveTelegramAuthenticationConverter();

    @Test
    void convert() {
        var expectedUser = new TelegramUser(1234567890L,
                                            Instant.ofEpochSecond(1677721600L),
                                            "Daniil",
                                            "Razorenov",
                                            "razornd",
                                            "https://telegram.org/img/t_logo.png");
        var telegramLoginRequest = MockServerHttpRequest.get("/login/telegram")
                                                        .queryParam("id", "1234567890")
                                                        .queryParam("first_name", "Daniil")
                                                        .queryParam("last_name", "Razorenov")
                                                        .queryParam("username", "razornd")
                                                        .queryParam("auth_date", "1677721600")
                                                        .queryParam("photo_url", "https://telegram.org/img/t_logo.png")
                                                        .queryParam("hash", "some-hash")
                                                        .build();
        var mockExchange = MockServerWebExchange.builder(telegramLoginRequest).build();

        var actual = converter.convert(mockExchange).block();

        assertThat(actual)
                .usingRecursiveComparison()
                .isEqualTo(new TelegramAuthenticationToken(expectedUser, "some-hash"));
    }

    @ParameterizedTest
    @CsvSource({"id", "auth_date", "hash"})
    void convertShouldReturnEmptyMonoOnMissingRequiredFields(String missingField) {
        var parameters = defaultParameters();
        parameters.remove(missingField);

        var telegramLoginRequest = MockServerHttpRequest.get("/login/telegram")
                                                        .queryParams(MultiValueMap.fromSingleValue(parameters))
                                                        .build();

        var mockExchange = MockServerWebExchange.builder(telegramLoginRequest).build();

        var actual = converter.convert(mockExchange).block();

        assertThat(actual).isNull();
    }

    @ParameterizedTest
    @CsvSource({"id, not-a-number",
                "auth_date, invalid-date"})
    void convertShouldReturnEmptyMonoOnNotParsableFields(String field, String invalidValue) {
        var parameters = defaultParameters();
        parameters.put(field, invalidValue);

        var telegramLoginRequest = MockServerHttpRequest.get("/login/telegram")
                                                        .queryParams(MultiValueMap.fromSingleValue(parameters))
                                                        .build();

        var mockExchange = MockServerWebExchange.builder(telegramLoginRequest).build();

        var actual = converter.convert(mockExchange).block();

        assertThat(actual).isNull();
    }

    private static HashMap<String, String> defaultParameters() {
        return new HashMap<>(Map.of("first_name", "Daniil",
                                    "last_name", "Razorenov",
                                    "username", "razornd",
                                    "id", "223654421",
                                    "auth_date", "1677721600",
                                    "photo_url", "https://telegram.org/img/t_logo.png",
                                    "hash", "some-hash"));
    }
}
