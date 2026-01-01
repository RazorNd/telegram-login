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

package io.github.razornd.telegramlogin.security.config;

import io.github.razornd.telegramlogin.security.*;
import org.jspecify.annotations.Nullable;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.authentication.*;
import org.springframework.security.web.server.context.ServerSecurityContextRepository;
import org.springframework.security.web.server.context.WebSessionServerSecurityContextRepository;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcher;

import java.util.List;
import java.util.Objects;
import java.util.function.Consumer;

import static org.springframework.security.web.server.util.matcher.ServerWebExchangeMatchers.pathMatchers;

/**
 * A configurer for Telegram Login in WebFlux applications.
 *
 * <p>This configurer provides support for authenticating users via the Telegram Login Widget.
 * It sets up a {@link AuthenticationWebFilter} and a {@link ReactiveTelegramAuthenticationManager}.
 *
 * @author Daniil Razorenov
 * @see ReactiveTelegramAuthenticationManager
 * @see ReactiveTelegramAuthenticationConverter
 * @see <a href="https://core.telegram.org/widgets/login">Telegram Login Widget</a>
 */
public class TelegramLoginServerSecurityConfigurer {

    @Nullable
    private HashValidator hashValidator;

    private final AuthDateExpirationValidator expirationValidator = new AuthDateExpirationValidator();

    @Nullable
    private List<TelegramAuthenticationValidator> validators;

    @Nullable
    private ServerAuthenticationSuccessHandler successHandler;

    @Nullable
    private ServerAuthenticationFailureHandler failureHandler;

    @Nullable
    private ServerWebExchangeMatcher requiresAuthenticationMatcher;

    @Nullable
    private ServerSecurityContextRepository securityContextRepository;

    @Nullable
    private ReactiveAuthenticationManager authenticationManager;

    private ServerAuthenticationConverter authenticationConverter = new ReactiveTelegramAuthenticationConverter();

    /**
     * Configures Telegram Login for the given {@link ServerHttpSecurity}.
     *
     * @param http       the security to configure
     * @param customizer a {@link Consumer} to customize the {@link TelegramLoginServerSecurityConfigurer}
     * @return the {@link ServerHttpSecurity} for further customizations
     */
    public static ServerHttpSecurity telegramLogin(ServerHttpSecurity http,
                                                   Consumer<TelegramLoginServerSecurityConfigurer> customizer) {
        var configurer = new TelegramLoginServerSecurityConfigurer();
        customizer.accept(configurer);
        return configurer.configure(http);
    }

    /**
     * Configures the validators to be used.
     *
     * @param validators the validators
     * @return the {@link TelegramLoginServerSecurityConfigurer} for further customizations
     */
    public TelegramLoginServerSecurityConfigurer validators(TelegramAuthenticationValidator... validators) {
        this.validators = List.of(validators);
        return this;
    }

    /**
     * Sets the {@link HashValidator} to be used.
     *
     * @param hashValidator the hash validator
     * @return the {@link TelegramLoginServerSecurityConfigurer} for further customizations
     */
    public TelegramLoginServerSecurityConfigurer hashValidator(HashValidator hashValidator) {
        this.hashValidator = hashValidator;
        return this;
    }

    /**
     * Sets the bot token to be used for hash validation.
     *
     * @param botToken the Telegram bot token
     * @return the {@link TelegramLoginServerSecurityConfigurer} for further customizations
     */
    public TelegramLoginServerSecurityConfigurer botToken(String botToken) {
        return hashValidator(new HashValidator(botToken));
    }

    /**
     * Sets the {@link ServerAuthenticationSuccessHandler} to be used.
     *
     * @param successHandler the success handler
     * @return the {@link TelegramLoginServerSecurityConfigurer} for further customizations
     */
    public TelegramLoginServerSecurityConfigurer successHandler(ServerAuthenticationSuccessHandler successHandler) {
        this.successHandler = successHandler;
        return this;
    }

    /**
     * Sets the {@link ServerAuthenticationFailureHandler} to be used.
     *
     * @param failureHandler the failure handler
     * @return the {@link TelegramLoginServerSecurityConfigurer} for further customizations
     */
    public TelegramLoginServerSecurityConfigurer failureHandler(ServerAuthenticationFailureHandler failureHandler) {
        this.failureHandler = failureHandler;
        return this;
    }

    /**
     * Sets the URL that the {@link AuthenticationWebFilter} will use for login requests.
     *
     * @param loginProcessingUrl the login processing URL
     * @return the {@link TelegramLoginServerSecurityConfigurer} for further customizations
     */
    public TelegramLoginServerSecurityConfigurer loginProcessingUrl(String loginProcessingUrl) {
        return requiresAuthenticationMatcher(pathMatchers(HttpMethod.GET, loginProcessingUrl));
    }

    /**
     * Sets the {@link ServerWebExchangeMatcher} to be used for matching login requests.
     *
     * @param requiresAuthenticationMatcher the request matcher
     * @return the {@link TelegramLoginServerSecurityConfigurer} for further customizations
     */
    public TelegramLoginServerSecurityConfigurer requiresAuthenticationMatcher(ServerWebExchangeMatcher requiresAuthenticationMatcher) {
        this.requiresAuthenticationMatcher = requiresAuthenticationMatcher;
        return this;
    }

    /**
     * Sets the {@link ServerSecurityContextRepository} to be used.
     *
     * @param securityContextRepository the security context repository
     * @return the {@link TelegramLoginServerSecurityConfigurer} for further customizations
     */
    public TelegramLoginServerSecurityConfigurer securityContextRepository(ServerSecurityContextRepository securityContextRepository) {
        this.securityContextRepository = securityContextRepository;
        return this;
    }

    /**
     * Sets the {@link ReactiveAuthenticationManager} to be used.
     *
     * @param authenticationManager the authentication manager
     * @return the {@link TelegramLoginServerSecurityConfigurer} for further customizations
     */
    public TelegramLoginServerSecurityConfigurer authenticationManager(ReactiveAuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
        return this;
    }

    /**
     * Sets the {@link ServerAuthenticationConverter} to be used.
     *
     * @param authenticationConverter the authentication converter
     * @return the {@link TelegramLoginServerSecurityConfigurer} for further customizations
     */
    public TelegramLoginServerSecurityConfigurer authenticationConverter(ServerAuthenticationConverter authenticationConverter) {
        this.authenticationConverter = authenticationConverter;
        return this;
    }

    private ServerHttpSecurity configure(ServerHttpSecurity http) {
        var webFilter = new AuthenticationWebFilter(getAuthenticationManager());
        webFilter.setRequiresAuthenticationMatcher(getRequiresAuthenticationMatcher());
        webFilter.setAuthenticationFailureHandler(getFailureHandler());
        webFilter.setServerAuthenticationConverter(authenticationConverter);
        webFilter.setAuthenticationSuccessHandler(getSuccessHandler());
        webFilter.setSecurityContextRepository(getSecurityContextRepository());
        return http.addFilterAt(webFilter, SecurityWebFiltersOrder.AUTHENTICATION);
    }

    private ServerWebExchangeMatcher getRequiresAuthenticationMatcher() {
        return Objects.requireNonNullElseGet(requiresAuthenticationMatcher,
                                             () -> pathMatchers(HttpMethod.GET, "/login/telegram"));
    }

    private ServerAuthenticationSuccessHandler getSuccessHandler() {
        return Objects.requireNonNullElseGet(successHandler, RedirectServerAuthenticationSuccessHandler::new);
    }

    private ServerAuthenticationFailureHandler getFailureHandler() {
        return Objects.requireNonNullElseGet(
                failureHandler,
                () -> new ServerAuthenticationEntryPointFailureHandler(new HttpStatusServerEntryPoint(HttpStatus.UNAUTHORIZED))
        );
    }

    private ServerSecurityContextRepository getSecurityContextRepository() {
        return Objects.requireNonNullElseGet(securityContextRepository, WebSessionServerSecurityContextRepository::new);
    }

    private ReactiveAuthenticationManager getAuthenticationManager() {
        if (authenticationManager != null) {
            return authenticationManager;
        }
        var validatorList = Objects.requireNonNullElseGet(validators,
                                                          () -> List.of(getHashValidator(), expirationValidator));

        return new ReactiveTelegramAuthenticationManager(new CompositeTelegramAuthenticationValidator(validatorList));
    }

    private HashValidator getHashValidator() {
        return Objects.requireNonNull(hashValidator, "HashValidator must be set");
    }
}
