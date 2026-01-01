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

import jakarta.servlet.http.HttpServletRequest;
import org.jspecify.annotations.Nullable;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;

import java.time.Instant;
import java.util.function.Function;

/**
 * An {@link AuthenticationConverter} that extracts Telegram authentication data from an
 * {@link HttpServletRequest} and converts it into a {@link TelegramAuthenticationToken}.
 *
 * <p>This converter expects the request to contain parameters provided by the Telegram
 * Login Widget, such as {@code id}, {@code auth_date}, and {@code hash}.
 *
 * @author Daniil Razorenov
 * @see TelegramAuthenticationToken
 * @see <a href="https://core.telegram.org/widgets/login">Telegram Login Widget</a>
 */
public class TelegramAuthenticationConverter implements AuthenticationConverter {

    private AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource = new WebAuthenticationDetailsSource();

    /**
     * Converts the given {@link HttpServletRequest} into a {@link TelegramAuthenticationToken}.
     * @param request the request to convert
     * @return the unauthenticated {@link TelegramAuthenticationToken}
     * @throws BadCredentialsException if any required parameters are missing or cannot be parsed
     */
    @Override
    @Nullable
    public TelegramAuthenticationToken convert(HttpServletRequest request) {
        var hash = getRequiredParameter(request, "hash", Function.identity());
        var telegramUser = new TelegramUser(getRequiredParameter(request, "id", Long::parseLong),
                                            getRequiredParameter(request,
                                                                 "auth_date",
                                                                 s -> Instant.ofEpochSecond(Long.parseLong(s))),
                                            request.getParameter("first_name"),
                                            request.getParameter("last_name"),
                                            request.getParameter("username"),
                                            request.getParameter("photo_url"));

        var authDetails = authenticationDetailsSource.buildDetails(request);

        return new TelegramAuthenticationToken(telegramUser, hash, authDetails);
    }

    /**
     * Sets the {@link AuthenticationDetailsSource} to use for building authentication details.
     * @param authenticationDetailsSource the authentication details source
     */
    public void setAuthenticationDetailsSource(AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource) {
        this.authenticationDetailsSource = authenticationDetailsSource;
    }

    private static <T> T getRequiredParameter(HttpServletRequest request,
                                              String parameterName,
                                              Function<String, T> converter) {
        var parameter = request.getParameter(parameterName);
        if (parameter == null) {
            throw new BadCredentialsException("Missing field '%s'".formatted(parameterName));
        }
        try {
            return converter.apply(parameter);
        } catch (Exception e) {
            throw new BadCredentialsException("Could not parse field '%s'".formatted(parameterName), e);
        }
    }

}
