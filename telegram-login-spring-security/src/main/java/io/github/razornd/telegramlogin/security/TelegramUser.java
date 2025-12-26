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
import org.springframework.security.core.AuthenticatedPrincipal;

import java.time.Instant;

/**
 * Represents a Telegram user as provided by the Telegram Login Widget.
 *
 * @param id        the unique identifier for this user
 * @param authDate  the date when the authentication was performed
 * @param hash      the hash value used to verify the authenticity of the data
 * @param firstName the user's first name
 * @param lastName  the user's last name (optional)
 * @param username  the user's username (optional)
 * @param photoUrl  the URL of the user's profile photo (optional)
 * @author Daniil Razorenov
 * @see <a href="https://core.telegram.org/widgets/login">Telegram Login Widget</a>
 */
public record TelegramUser(
        long id,
        Instant authDate,
        String hash,
        @Nullable
        String firstName,
        @Nullable
        String lastName,
        @Nullable
        String username,
        @Nullable
        String photoUrl
) implements AuthenticatedPrincipal {
    /**
     * Returns the user's ID as the principal's name.
     * @return the string representation of the user ID
     */
    @Override
    public String getName() {
        return Long.toString(id);
    }
}
