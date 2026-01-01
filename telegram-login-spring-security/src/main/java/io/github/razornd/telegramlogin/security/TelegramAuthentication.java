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

import org.jspecify.annotations.Nullable;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

/**
 * An implementation of {@link org.springframework.security.core.Authentication} for a
 * successfully authenticated Telegram user.
 *
 * @author Daniil Razorenov
 * @see TelegramPrincipal
 * @see TelegramUser
 */
public class TelegramAuthentication extends AbstractAuthenticationToken {

    /**
     * The authenticated Telegram principal associated with this authentication token.
     * Represents the principal of the current authentication context.
     *
     * @see TelegramPrincipal
     */
    private final TelegramPrincipal principal;

    /**
     * Creates a new authenticated token for the specified {@link TelegramPrincipal}.
     *
     * @param principal   the authenticated Telegram principal
     * @param authorities the authorities granted to the user
     */
    public TelegramAuthentication(TelegramPrincipal principal, Collection<? extends GrantedAuthority> authorities) {
        super(authorities);
        this.principal = principal;
        setAuthenticated(true);
    }

    /**
     * Returns the Telegram ID of the authenticated user as the name of this principal.
     * @return the Telegram ID as a {@link String}
     */
    @Override
    public String getName() {
        return String.valueOf(principal.getTelegramId());
    }

    /**
     * Telegram authentication does not use credentials after the initial validation.
     *
     * @return {@code null}
     */
    @Override
    @Nullable
    public Object getCredentials() {
        return null;
    }

    /**
     * Returns the authenticated {@link TelegramPrincipal}.
     *
     * @return the principal
     */
    @Override
    public TelegramPrincipal getPrincipal() {
        return principal;
    }
}
