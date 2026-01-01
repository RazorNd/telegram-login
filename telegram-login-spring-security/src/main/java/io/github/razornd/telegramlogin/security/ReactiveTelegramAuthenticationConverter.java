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

import org.springframework.security.core.Authentication;
import org.springframework.security.web.server.authentication.ServerAuthenticationConverter;
import org.springframework.util.MultiValueMap;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.time.Instant;
import java.util.Objects;
import java.util.function.Function;

/**
 * A {@link ServerAuthenticationConverter} that extracts Telegram authentication data from a
 * {@link ServerWebExchange} and converts it into a {@link TelegramAuthenticationToken}.
 *
 * <p>This converter expects the query parameters to contain data provided by the Telegram
 * Login Widget, such as {@code id}, {@code auth_date}, and {@code hash}.
 *
 * @author Daniil Razorenov
 * @see TelegramAuthenticationToken
 * @see <a href="https://core.telegram.org/widgets/login">Telegram Login Widget</a>
 */
public class ReactiveTelegramAuthenticationConverter implements ServerAuthenticationConverter {

    /**
     * Converts the given {@link ServerWebExchange} into a {@link TelegramAuthenticationToken}.
     * @param exchange the exchange to convert
     * @return a {@link Mono} containing the unauthenticated {@link TelegramAuthenticationToken},
     * or an empty {@link Mono} if the required parameters are missing or invalid
     */
    @Override
    public Mono<Authentication> convert(ServerWebExchange exchange) {
        var queryParams = exchange.getRequest().getQueryParams();
        try {
            return doConvert(queryParams);
        } catch (Exception e) {
            return Mono.empty();
        }
    }

    private Mono<Authentication> doConvert(MultiValueMap<String, String> queryParams) {
        var hash = getRequiredField(queryParams, "hash", Function.identity());

        var telegramUser = new TelegramUser(
                getRequiredField(queryParams, "id", Long::parseLong),
                getRequiredField(queryParams, "auth_date", s -> Instant.ofEpochSecond(Long.parseLong(s))),
                queryParams.getFirst("first_name"),
                queryParams.getFirst("last_name"),
                queryParams.getFirst("username"),
                queryParams.getFirst("photo_url")
        );

        return Mono.just(new TelegramAuthenticationToken(telegramUser, hash));
    }

    private <T> T getRequiredField(MultiValueMap<String, String> params, String field, Function<String, T> mapper) {
        var fieldValue = Objects.requireNonNull(params.getFirst(field));
        return mapper.apply(fieldValue);
    }
}
