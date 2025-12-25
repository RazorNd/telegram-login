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

package io.github.razornd.telegramlogin.security.config;

import io.github.razornd.telegramlogin.security.*;
import jakarta.servlet.http.HttpServletRequest;
import org.jspecify.annotations.Nullable;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationFilter;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.context.DelegatingSecurityContextRepository;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.RequestAttributeSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;

import java.util.List;
import java.util.Objects;

public class TelegramLoginConfigurer<B extends HttpSecurityBuilder<B>>
        extends AbstractHttpConfigurer<TelegramLoginConfigurer<B>, B> {

    @Nullable
    private HashValidator hashValidator;
    @Nullable
    private List<TelegramAuthenticationValidator> validators;
    @Nullable
    private AuthenticationSuccessHandler successHandler;
    @Nullable
    private AuthenticationFailureHandler failureHandler;
    @Nullable
    private RequestMatcher requestMatcher;
    @Nullable
    private SecurityContextRepository securityContextRepository;

    @Nullable
    private AuthenticationManager authenticationManager;

    private AuthenticationConverter authenticationConverter = new TelegramAuthenticationConverter();

    public TelegramLoginConfigurer<B> validators(TelegramAuthenticationValidator... validators) {
        this.validators = List.of(validators);
        return this;
    }

    public TelegramLoginConfigurer<B> botToken(String botToken) {
        return hashValidator(new HashValidator(botToken));
    }

    public TelegramLoginConfigurer<B> hashValidator(HashValidator hashValidator) {
        this.hashValidator = hashValidator;
        return this;
    }

    public TelegramLoginConfigurer<B> successHandler(AuthenticationSuccessHandler successHandler) {
        this.successHandler = successHandler;
        return this;
    }

    public TelegramLoginConfigurer<B> failureHandler(AuthenticationFailureHandler failureHandler) {
        this.failureHandler = failureHandler;
        return this;
    }

    public TelegramLoginConfigurer<B> authenticationDetailsSource(AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource) {
        if (authenticationConverter instanceof TelegramAuthenticationConverter telegramAuthConverter) {
            telegramAuthConverter.setAuthenticationDetailsSource(authenticationDetailsSource);
        }
        return this;
    }

    public TelegramLoginConfigurer<B> loginProcessingUrl(String loginProcessingUrl) {
        return requestMatcher(createLoginRequestMatcher(loginProcessingUrl));
    }

    public TelegramLoginConfigurer<B> requestMatcher(PathPatternRequestMatcher requestMatcher) {
        this.requestMatcher = requestMatcher;
        return this;
    }

    public TelegramLoginConfigurer<B> securityContextRepository(SecurityContextRepository securityContextRepository) {
        this.securityContextRepository = securityContextRepository;
        return this;
    }

    public TelegramLoginConfigurer<B> authenticationManager(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
        return this;
    }

    public TelegramLoginConfigurer<B> authenticationConverter(AuthenticationConverter authenticationConverter) {
        this.authenticationConverter = authenticationConverter;
        return this;
    }

    @Override
    public void init(B http) {
        http.authenticationProvider(getAuthenticationProvider());
    }

    @Override
    public void configure(B http) {
        var authManager = getAuthenticationManager();

        var filter = new AuthenticationFilter(authManager, authenticationConverter);

        filter.setRequestMatcher(getRequestMatcher());

        filter.setSecurityContextRepository(getSecurityContextRepository());
        filter.setSecurityContextHolderStrategy(getSecurityContextHolderStrategy());

        if (successHandler != null) {
            filter.setSuccessHandler(successHandler);
        }
        if (failureHandler != null) {
            filter.setFailureHandler(failureHandler);
        }

        http.addFilter(postProcess(filter));
    }

    private PathPatternRequestMatcher createLoginRequestMatcher(String loginProcessingUrl) {
        return getRequestMatcherBuilder().matcher(HttpMethod.GET, loginProcessingUrl);
    }

    private AuthenticationManager getAuthenticationManager() {
        return Objects.requireNonNullElseGet(authenticationManager,
                                             () -> getBuilder().getSharedObject(AuthenticationManager.class));
    }

    private RequestMatcher getRequestMatcher() {
        if (requestMatcher == null) {
            requestMatcher = createLoginRequestMatcher("/login/telegram");
        }
        return requestMatcher;
    }

    private TelegramAuthenticationProvider getAuthenticationProvider() {
        if (validators == null) {
            validators = defaultAuthValidators();
        }
        return new TelegramAuthenticationProvider(new CompositeTelegramAuthenticationValidator(validators));
    }

    private SecurityContextRepository getSecurityContextRepository() {
        if (securityContextRepository != null) {
            return securityContextRepository;
        }
        var contextRepository = getBuilder().getSharedObject(SecurityContextRepository.class);
        //noinspection ConstantValue
        if (contextRepository != null) {
            return contextRepository;
        }
        return new DelegatingSecurityContextRepository(new RequestAttributeSecurityContextRepository(),
                                                       new HttpSessionSecurityContextRepository());
    }

    private List<TelegramAuthenticationValidator> defaultAuthValidators() {
        Assert.notNull(hashValidator, "Bot token or HashValidator must be set");
        return List.of(hashValidator, new AuthDateExpirationValidator());
    }

}
