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

import org.jspecify.annotations.Nullable;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

/**
 * An {@link org.springframework.security.core.Authentication} request for Telegram login.
 *
 * <p>This token is initially unauthenticated and contains the user information provided
 * by the Telegram login widget. It is subsequently processed by a
 * {@link TelegramAuthenticationProvider}.
 *
 * @author Daniil Razorenov
 * @see TelegramAuthenticationProvider
 */
public class TelegramAuthenticationToken extends AbstractAuthenticationToken {

    /**
     * The {@link TelegramUser} instance representing the authenticated user's details
     * as provided by the Telegram Login Widget.
     * <p>
     * This field is immutable and contains user-specific information such as the ID,
     * authentication date, and optional metadata like first name, last name, username,
     * and profile photo URL. It is used as the principal in the authentication process.
     */
    private final TelegramUser principal;

    /**
     * Creates a new unauthenticated token for the given {@link TelegramUser}.
     *
     * @param principal the Telegram user to authenticate
     */
    public TelegramAuthenticationToken(TelegramUser principal) {
        this(principal, null);
    }

    /**
     * Creates a new unauthenticated token for the given {@link TelegramUser} and details.
     *
     * @param principal the Telegram user to authenticate
     * @param details   the authentication details (e.g. remote address, session ID)
     */
    public TelegramAuthenticationToken(TelegramUser principal, @Nullable Object details) {
        super((Collection<? extends GrantedAuthority>) null);
        this.principal = principal;
        setAuthenticated(false);
        setDetails(details);
    }

    /**
     * Telegram authentication does not use credentials.
     *
     * @return {@code null}
     */
    @Override
    @Nullable
    public String getCredentials() {
        return null;
    }

    /**
     * Returns the {@link TelegramUser} to be authenticated.
     *
     * @return the principal
     */
    @Override
    public TelegramUser getPrincipal() {
        return principal;
    }
}
