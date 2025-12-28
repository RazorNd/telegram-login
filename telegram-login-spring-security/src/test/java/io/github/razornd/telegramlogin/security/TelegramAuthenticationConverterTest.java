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

import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.springframework.mock.web.MockServletContext;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.util.MultiValueMap;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

class TelegramAuthenticationConverterTest {

    TelegramAuthenticationConverter converter = new TelegramAuthenticationConverter();

    @Test
    void convert() {
        var expectedUser = new TelegramUser(1234567890L,
                                            Instant.ofEpochSecond(1677721600L),
                                            "Daniil",
                                            "Razorenov",
                                            "razornd",
                                            null);
        var telegramAuthRequest = MockMvcRequestBuilders.get("/auth/telegram")
                                                        .queryParam("id", "1234567890")
                                                        .queryParam("first_name", "Daniil")
                                                        .queryParam("last_name", "Razorenov")
                                                        .queryParam("username", "razornd")
                                                        .queryParam("auth_date", "1677721600")
                                                        .queryParam("hash", "some-hash")
                                                        .buildRequest(new MockServletContext());
        var details = new WebAuthenticationDetails(telegramAuthRequest);


        var actual = converter.convert(telegramAuthRequest);

        assertThat(actual)
                .usingRecursiveComparison()
                .isEqualTo(new TelegramAuthenticationToken(expectedUser, "some-hash", details));
    }

    @Test
    void convertShouldUseCustomAuthDetailsSource() {
        var telegramAuthRequest = MockMvcRequestBuilders.get("/auth/telegram")
                                                        .queryParam("id", "1234567890")
                                                        .queryParam("first_name", "Daniil")
                                                        .queryParam("last_name", "Razorenov")
                                                        .queryParam("username", "razornd")
                                                        .queryParam("auth_date", "1677721600")
                                                        .queryParam("hash", "some-hash")
                                                        .buildRequest(new MockServletContext());

        Object customDetails = new Object();
        AuthenticationDetailsSource<HttpServletRequest, ?> customDetailsSource = mock();

        doReturn(customDetails).when(customDetailsSource).buildDetails(any());

        converter.setAuthenticationDetailsSource(customDetailsSource);

        var actual = converter.convert(telegramAuthRequest);

        assertThat(actual).extracting(AbstractAuthenticationToken::getDetails).isSameAs(customDetails);
        verify(customDetailsSource).buildDetails(telegramAuthRequest);
    }

    @ParameterizedTest
    @CsvSource({"id, Missing field 'id'",
                "auth_date, Missing field 'auth_date'",
                "hash, Missing field 'hash'"})
    void convertShouldThrowExceptionWhenRequiredFieldIsMissing(String missingField, String expectedMessage) {
        var parameters = new HashMap<>(Map.of("first_name", "Daniil",
                                              "last_name", "Razorenov",
                                              "username", "razornd",
                                              "id", "223654421",
                                              "auth_date", "1677721600",
                                              "hash", "some-hash"));
        parameters.remove(missingField);

        var telegramAuthRequest = MockMvcRequestBuilders.get("/auth/telegram")
                                                        .queryParams(MultiValueMap.fromSingleValue(parameters))
                                                        .buildRequest(new MockServletContext());

        assertThatThrownBy(() -> converter.convert(telegramAuthRequest))
                .isInstanceOf(BadCredentialsException.class)
                .hasMessage(expectedMessage);
    }

    @ParameterizedTest
    @CsvSource({"id, not-a-number",
                "auth_date, invalid-date"})
    void convertShouldThrowExceptionWhenFieldIsNotParsable(String field, String invalidValue) {
        var parameters = new HashMap<>(Map.of("first_name", "Daniil",
                                              "last_name", "Razorenov",
                                              "username", "razornd",
                                              "id", "223654421",
                                              "auth_date", "1677721600",
                                              "hash", "some-hash"));

        parameters.put(field, invalidValue);

        var telegramAuthRequest = MockMvcRequestBuilders.get("/auth/telegram")
                                                        .queryParams(MultiValueMap.fromSingleValue(parameters))
                                                        .buildRequest(new MockServletContext());

        assertThatThrownBy(() -> converter.convert(telegramAuthRequest))
                .isInstanceOf(BadCredentialsException.class)
                .hasMessage("Could not parse field '%s'", field);
    }


}
