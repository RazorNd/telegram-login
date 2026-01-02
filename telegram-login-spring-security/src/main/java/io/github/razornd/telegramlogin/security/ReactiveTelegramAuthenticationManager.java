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

import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.core.Authentication;
import reactor.core.publisher.Mono;

import java.util.Set;

/**
 * A {@link ReactiveAuthenticationManager} for Telegram authentication.
 *
 * <p>This manager validates a {@link TelegramAuthenticationToken} using a
 * {@link TelegramAuthenticationValidator}. If validation passes, it returns a
 * {@link TelegramAuthentication}.
 *
 * @author Daniil Razorenov
 * @see TelegramAuthenticationToken
 * @see TelegramAuthentication
 * @see TelegramAuthenticationValidator
 */
public class ReactiveTelegramAuthenticationManager implements ReactiveAuthenticationManager {

    private final TelegramAuthenticationValidator validator;

    private ReactiveTelegramUserService userService =
            new ReactiveAdapterTelegramUserService(new SimpleTelegramUserService());

    /**
     * Creates a new {@link ReactiveTelegramAuthenticationManager} with the given
     * {@link TelegramAuthenticationValidator}.
     *
     * @param validator the validator to use
     */
    public ReactiveTelegramAuthenticationManager(TelegramAuthenticationValidator validator) {
        this.validator = validator;
    }

    /**
     * Authenticates the given {@link Authentication} object.
     *
     * @param authentication the authentication request object
     * @return a {@link Mono} containing the successfully authenticated {@link TelegramAuthentication},
     * or an error {@link Mono} if authentication fails
     */
    @Override
    public Mono<Authentication> authenticate(Authentication authentication) {
        if (!(authentication instanceof TelegramAuthenticationToken token)) {
            return Mono.empty();
        }

        if (validator.validate(token) instanceof ValidationResult.Invalid invalid) {
            return Mono.error(new BadCredentialsException(invalid.reason()));
        }

        return userService.loadUser(token.getPrincipal()).map(this::createAuthority);
    }

    /**
     * Sets the {@link ReactiveTelegramUserService} to use for loading user details.
     *
     * @param userService the reactive user service to use
     */
    public void setUserService(ReactiveTelegramUserService userService) {
        this.userService = userService;
    }

    private Authentication createAuthority(TelegramPrincipal principal) {
        return new TelegramAuthentication(principal, Set.copyOf(principal.getAuthorities()));
    }
}
