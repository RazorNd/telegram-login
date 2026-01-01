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
import jakarta.servlet.http.HttpServletRequest;
import org.jspecify.annotations.Nullable;
import org.springframework.context.ApplicationContext;
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

/**
 * An {@link AbstractHttpConfigurer} for Telegram Login.
 *
 * <p>This configurer provides support for authenticating users via the Telegram Login Widget.
 * It sets up a {@link AuthenticationFilter} and a {@link TelegramAuthenticationProvider}.
 *
 * <h2>Example Usage</h2>
 * <pre>
 * &#064;Configuration
 * &#064;EnableWebSecurity
 * public class SecurityConfig {
 *
 *     &#064;Bean
 *     public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
 *         http
 *             .with(new TelegramLoginConfigurer&lt;&gt;(), (telegram) -&gt; telegram
 *                 .botToken("YOUR_BOT_TOKEN")
 *             )
 *             .authorizeHttpRequests((authorize) -&gt; authorize
 *                 .anyRequest().authenticated()
 *             );
 *         return http.build();
 *     }
 * }
 * </pre>
 *
 * @param <B> the type of {@link HttpSecurityBuilder}
 * @author Daniil Razorenov
 * @see TelegramAuthenticationProvider
 * @see TelegramAuthenticationConverter
 * @see <a href="https://core.telegram.org/widgets/login">Telegram Login Widget</a>
 */
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

    /**
     * Configures the validators to be used.
     * @param validators the validators
     * @return the {@link TelegramLoginConfigurer} for further customizations
     */
    public TelegramLoginConfigurer<B> validators(TelegramAuthenticationValidator... validators) {
        this.validators = List.of(validators);
        return this;
    }

    /**
     * Sets the bot token to be used for hash validation.
     * @param botToken the Telegram bot token
     * @return the {@link TelegramLoginConfigurer} for further customizations
     */
    public TelegramLoginConfigurer<B> botToken(String botToken) {
        return hashValidator(new HashValidator(botToken));
    }

    /**
     * Sets the {@link HashValidator} to be used.
     * @param hashValidator the hash validator
     * @return the {@link TelegramLoginConfigurer} for further customizations
     */
    public TelegramLoginConfigurer<B> hashValidator(HashValidator hashValidator) {
        this.hashValidator = hashValidator;
        return this;
    }

    /**
     * Sets the {@link AuthenticationSuccessHandler} to be used.
     * @param successHandler the success handler
     * @return the {@link TelegramLoginConfigurer} for further customizations
     */
    public TelegramLoginConfigurer<B> successHandler(AuthenticationSuccessHandler successHandler) {
        this.successHandler = successHandler;
        return this;
    }

    /**
     * Sets the {@link AuthenticationFailureHandler} to be used.
     * @param failureHandler the failure handler
     * @return the {@link TelegramLoginConfigurer} for further customizations
     */
    public TelegramLoginConfigurer<B> failureHandler(AuthenticationFailureHandler failureHandler) {
        this.failureHandler = failureHandler;
        return this;
    }

    /**
     * Sets the {@link AuthenticationDetailsSource} to be used.
     * @param authenticationDetailsSource the authentication details source
     * @return the {@link TelegramLoginConfigurer} for further customizations
     */
    public TelegramLoginConfigurer<B> authenticationDetailsSource(AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource) {
        if (authenticationConverter instanceof TelegramAuthenticationConverter telegramAuthConverter) {
            telegramAuthConverter.setAuthenticationDetailsSource(authenticationDetailsSource);
        }
        return this;
    }

    /**
     * Sets the URL that the {@link AuthenticationFilter} will use for login requests.
     * @param loginProcessingUrl the login processing URL
     * @return the {@link TelegramLoginConfigurer} for further customizations
     */
    public TelegramLoginConfigurer<B> loginProcessingUrl(String loginProcessingUrl) {
        return requestMatcher(createLoginRequestMatcher(loginProcessingUrl));
    }

    /**
     * Sets the {@link PathPatternRequestMatcher} to be used for matching login requests.
     * @param requestMatcher the request matcher
     * @return the {@link TelegramLoginConfigurer} for further customizations
     */
    public TelegramLoginConfigurer<B> requestMatcher(PathPatternRequestMatcher requestMatcher) {
        this.requestMatcher = requestMatcher;
        return this;
    }

    /**
     * Sets the {@link SecurityContextRepository} to be used.
     * @param securityContextRepository the security context repository
     * @return the {@link TelegramLoginConfigurer} for further customizations
     */
    public TelegramLoginConfigurer<B> securityContextRepository(SecurityContextRepository securityContextRepository) {
        this.securityContextRepository = securityContextRepository;
        return this;
    }

    /**
     * Sets the {@link AuthenticationManager} to be used.
     * @param authenticationManager the authentication manager
     * @return the {@link TelegramLoginConfigurer} for further customizations
     */
    public TelegramLoginConfigurer<B> authenticationManager(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
        return this;
    }

    /**
     * Sets the {@link AuthenticationConverter} to be used.
     * @param authenticationConverter the authentication converter
     * @return the {@link TelegramLoginConfigurer} for further customizations
     */
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
        var hashValidator = this.hashValidator;
        if (hashValidator == null) {
            hashValidator = getBeanOrNull(HashValidator.class);
        }
        Assert.notNull(hashValidator, "Bot token or HashValidator must be set");
        return List.of(hashValidator, new AuthDateExpirationValidator());
    }

    @Nullable
    private <C> C getBeanOrNull(Class<C> clazz) {
        ApplicationContext context = getBuilder().getSharedObject(ApplicationContext.class);
        //noinspection ConstantValue
        if (context == null) {
            return null;
        }
        return context.getBeanProvider(clazz).getIfUnique();
    }

}
