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
     * Represents the hash value used to verify the authenticity of the authentication data in Telegram
     * authentication. This value provides a mechanism to ensure the integrity and authenticity of the
     * provided authentication details. The hash may be {@code null} if not set or if credentials have
     * been erased.
     *
     * @see TelegramAuthenticationToken#getCredentials()
     * @see TelegramAuthenticationToken#eraseCredentials()
     */
    @Nullable
    private String hash;

    /**
     * Constructs a new unauthenticated Telegram authentication token for the given user information.
     *
     * @param principal the Telegram user being authenticated
     * @param hash      the hash value used to verify the authenticity of the authentication data
     */
    public TelegramAuthenticationToken(TelegramUser principal, String hash) {
        this(principal, hash, null);
    }

    /**
     * Creates a new unauthenticated token for the given {@link TelegramUser} and details.
     *
     * @param principal the Telegram user to authenticate
     * @param hash      the hash value used to verify the authenticity of the authentication data
     * @param details   the authentication details (e.g. remote address, session ID)
     */
    public TelegramAuthenticationToken(TelegramUser principal, String hash, @Nullable Object details) {
        super((Collection<? extends GrantedAuthority>) null);
        this.principal = principal;
        this.hash = hash;
        setAuthenticated(false);
        setDetails(details);
    }

    /**
     * Retrieves the hash value used to verify the authenticity of the authentication data.
     *
     * @return the hash value if available, or {@code null} if not set
     */
    @Override
    @Nullable
    public String getCredentials() {
        return hash;
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

    /**
     * Erases sensitive authentication credentials from the token by setting the hash value to {@code null}.
     * <p>
     * This method is typically invoked after the authentication process has completed to minimize the risk
     * of exposing sensitive authentication data such as verification hashes. Subsequent calls to
     * {@link #getCredentials()} will return {@code null}.
     */
    @Override
    public void eraseCredentials() {
        this.hash = null;
    }
}
