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
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.FactorGrantedAuthority;

import java.util.ArrayList;
import java.util.Set;

/**
 * An {@link AuthenticationProvider} for Telegram authentication.
 *
 * <p>This provider validates a {@link TelegramAuthenticationToken} using a
 * {@link TelegramAuthenticationValidator}. If validation passes, it returns a
 * {@link TelegramAuthentication} with the {@code TELEGRAM} authority factor.
 *
 * @author Daniil Razorenov
 * @see TelegramAuthenticationToken
 * @see TelegramAuthentication
 * @see TelegramAuthenticationValidator
 */
public class TelegramAuthenticationProvider implements AuthenticationProvider {

    /**
     * The factor granted to successfully authenticated Telegram users.
     */
    public static final String AUTHENTICATION_FACTOR = "TELEGRAM";

    private final TelegramAuthenticationValidator validator;

    private TelegramUserService userService = new SimpleTelegramUserService();

    /**
     * Creates a new {@link TelegramAuthenticationProvider} with the given {@link TelegramAuthenticationValidator}.
     * @param validator the validator to use
     */
    public TelegramAuthenticationProvider(TelegramAuthenticationValidator validator) {
        this.validator = validator;
    }

    /**
     * Authenticates the given {@link Authentication} object.
     * @param authentication the authentication request object
     * @return a successfully authenticated {@link TelegramAuthentication}
     * @throws AuthenticationException if authentication fails
     */
    @Override
    @Nullable
    public TelegramAuthentication authenticate(Authentication authentication) throws AuthenticationException {
        var telegramAuthToken = (TelegramAuthenticationToken) authentication;

        var validationResult = validator.validate(telegramAuthToken);
        if (validationResult instanceof ValidationResult.Invalid invalid) {
            throw new BadCredentialsException(invalid.reason());
        }

        var fetchedUser = userService.loadUser(telegramAuthToken.getPrincipal());

        var authorities = new ArrayList<GrantedAuthority>(fetchedUser.getAuthorities());
        authorities.add(FactorGrantedAuthority.fromFactor(AUTHENTICATION_FACTOR));

        return new TelegramAuthentication(fetchedUser, Set.copyOf(authorities));
    }

    /**
     * Checks if this provider supports the given authentication type.
     * @param authentication the authentication class to check
     * @return {@code true} if the class is {@link TelegramAuthenticationToken} or a subclass
     */
    @Override
    public boolean supports(Class<?> authentication) {
        return TelegramAuthenticationToken.class.isAssignableFrom(authentication);
    }

    /**
     * Sets the {@link TelegramUserService} to use for loading user details.
     *
     * @param userService the user service to use
     */
    public void setUserService(TelegramUserService userService) {
        this.userService = userService;
    }
}
