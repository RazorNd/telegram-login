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
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.mock.web.MockServletContext;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.authentication.AuthenticationEntryPointFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.context.DelegatingSecurityContextRepository;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.RequestAttributeSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.context.support.AnnotationConfigWebApplicationContext;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.HexFormat;
import java.util.Map;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.AdditionalAnswers.returnsFirstArg;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.authenticated;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher.pathPattern;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.options;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

class TelegramLoginConfigurerTest {

    private static final String BOT_TOKEN = "token";

    private WebApplicationContext createContext(Class<?>... configClasses) {
        AnnotationConfigWebApplicationContext context = new AnnotationConfigWebApplicationContext();
        context.setServletContext(new MockServletContext());
        context.register(configClasses);
        context.refresh();
        return context;
    }

    private MockMvc createMockMvc(WebApplicationContext context) {
        return MockMvcBuilders.webAppContextSetup(context)
                              .apply(springSecurity())
                              .build();
    }

    @Test
    void shouldAuthenticateWithDefaultUrl() throws Exception {
        var context = createContext(DefaultConfig.class);
        var mockMvc = createMockMvc(context);

        var date = currentDate();

        mockMvc.perform(get("/login/telegram")
                                .param("id", "6976597")
                                .param("auth_date", date)
                                .param("hash", calcHash(Map.of("id", "6976597", "auth_date", date))))
               .andExpect(authenticated().withUsername("6976597"));
    }

    @Test
    void shouldAuthenticateWithCustomUrl() throws Exception {
        var context = createContext(CustomUrlConfig.class);
        var mockMvc = createMockMvc(context);

        var date = currentDate();

        mockMvc.perform(get("/custom/login")
                                .param("id", "71603")
                                .param("auth_date", date)
                                .param("hash", calcHash(Map.of("id", "71603", "auth_date", date))))
               .andExpect(authenticated().withUsername("71603"));
    }

    @Test
    void shouldInvokeSuccessHandler() throws Exception {
        var context = createContext(SuccessHandlerConfig.class);
        var mockMvc = createMockMvc(context);

        var date = currentDate();

        mockMvc.perform(get("/login/telegram")
                                .param("id", "11761")
                                .param("auth_date", date)
                                .param("hash", calcHash(Map.of("id", "11761", "auth_date", date))))
               .andExpect(authenticated().withUsername("11761"));

        verify(context.getBean(AuthenticationSuccessHandler.class)).onAuthenticationSuccess(any(), any(), any(), any());
    }

    @Test
    void shouldInvokeFailureHandler() throws Exception {
        var context = createContext(FailureHandlerConfig.class);
        var mockMvc = createMockMvc(context);

        var date = currentDate();

        mockMvc.perform(get("/login/telegram")
                                .param("id", "53281216")
                                .param("auth_date", date)
                                .param("hash", "bad04a54"))
               .andExpect(status().isPaymentRequired());
    }

    @Test
    void shouldInvokeCustomValidator() throws Exception {
        var context = createContext(CustomValidatorConfig.class);
        var mockMvc = createMockMvc(context);

        var date = currentDate();

        mockMvc.perform(get("/login/telegram")
                                .param("id", "42")
                                .param("auth_date", date)
                                .param("hash", calcHash(Map.of("id", "42", "auth_date", date))))
               .andExpect(authenticated().withUsername("42"));

        verify(context.getBean(TelegramAuthenticationValidator.class)).validate(any());
    }

    @Test
    void shouldInvokeCustomAuthenticationManager() throws Exception {
        var context = createContext(CustomAuthenticationManagerConfig.class);
        var mockMvc = createMockMvc(context);
        var authTokenCaptor = ArgumentCaptor.forClass(TelegramAuthenticationToken.class);
        var date = currentDate();
        var expectedUser = new TelegramUser(42L,
                                            Instant.ofEpochSecond(Long.parseLong(date)),
                                            "any",
                                            null,
                                            null,
                                            null,
                                            null);

        mockMvc.perform(get("/login/telegram")
                                .param("id", "42")
                                .param("auth_date", date)
                                .param("hash", "any"))
               .andExpect(authenticated());

        verify(context.getBean(AuthenticationManager.class)).authenticate(authTokenCaptor.capture());

        assertThat(authTokenCaptor.getValue())
                .usingRecursiveComparison()
                .ignoringFields("details")
                .isEqualTo(new TelegramAuthenticationToken(expectedUser));
    }

    @Test
    void shouldInvokeCustomAuthenticationConverter() throws Exception {
        var context = createContext(CustomAuthenticationConverterConfig.class);
        var mockMvc = createMockMvc(context);

        mockMvc.perform(get("/login/telegram"))
               .andExpect(authenticated());

        verify(context.getBean(AuthenticationConverter.class)).convert(any());
    }

    @Test
    void shouldInvokeCustomSecurityContextRepository() throws Exception {
        var context = createContext(CustomSecurityContextRepositoryConfig.class);
        var mockMvc = createMockMvc(context);

        var date = currentDate();
        mockMvc.perform(get("/login/telegram")
                                .param("id", "42")
                                .param("auth_date", date)
                                .param("hash", calcHash(Map.of("id", "42", "auth_date", date))))
               .andExpect(authenticated());

        verify(context.getBean(SecurityContextRepository.class)).saveContext(any(), any(), any());
    }

    @Test
    void shouldSetCustomAuthenticationDetailsSource() throws Exception {
        var context = createContext(CustomAuthenticationDetailsSourceConfig.class);
        var mockMvc = createMockMvc(context);

        var date = currentDate();
        mockMvc.perform(get("/login/telegram")
                                .param("id", "42")
                                .param("auth_date", date)
                                .param("hash", calcHash(Map.of("id", "42", "auth_date", date))))
               .andExpect(authenticated());

        //noinspection unchecked
        verify(context.getBean(AuthenticationDetailsSource.class)).buildDetails(any());
    }

    @Test
    void shouldInvokeCustomHashValidator() throws Exception {
        var context = createContext(CustomHashValidatorConfig.class);
        var mockMvc = createMockMvc(context);

        var date = currentDate();

        mockMvc.perform(get("/login/telegram")
                                .param("id", "42")
                                .param("auth_date", date)
                                .param("hash", "custom-hash"))
               .andExpect(authenticated());

        verify(context.getBean(HashValidator.class)).validate(any());
    }

    @Test
    void shouldAuthenticateWithCustomRequestMatcher() throws Exception {
        var context = createContext(CustomRequestMatcherConfig.class);
        var mockMvc = createMockMvc(context);

        var date = currentDate();

        mockMvc.perform(options("/custom/path")
                                .param("id", "42")
                                .param("auth_date", date)
                                .param("hash", calcHash(Map.of("id", "42", "auth_date", date))))
               .andExpect(authenticated());
    }

    @Configuration
    @EnableWebSecurity
    static class DefaultConfig {

        @Bean
        public SecurityFilterChain securityFilterChain(HttpSecurity http) {
            http.with(new TelegramLoginConfigurer<>(), telegram -> telegram
                    .botToken(BOT_TOKEN)
            );
            return http.build();
        }

    }

    @Configuration
    @EnableWebSecurity
    static class CustomUrlConfig {

        @Bean
        public SecurityFilterChain securityFilterChain(HttpSecurity http) {
            http.with(new TelegramLoginConfigurer<>(), telegram -> telegram
                    .loginProcessingUrl("/custom/login")
                    .botToken(BOT_TOKEN)
            );
            return http.build();
        }

    }

    @Configuration
    @EnableWebSecurity
    static class SuccessHandlerConfig {

        @Bean
        public AuthenticationSuccessHandler successHandler() {
            return mock(AuthenticationSuccessHandler.class);
        }

        @Bean
        public SecurityFilterChain securityFilterChain(HttpSecurity http) {
            http.with(new TelegramLoginConfigurer<>(), telegram -> telegram
                    .successHandler(successHandler())
                    .botToken(BOT_TOKEN)
            );
            return http.build();
        }
    }

    @Configuration
    @EnableWebSecurity
    static class FailureHandlerConfig {

        @Bean
        SecurityFilterChain securityFilterChain(HttpSecurity http) {
            http.with(new TelegramLoginConfigurer<>(), telegram -> telegram
                    .failureHandler(new AuthenticationEntryPointFailureHandler(new HttpStatusEntryPoint(HttpStatus.PAYMENT_REQUIRED)))
                    .botToken(BOT_TOKEN)
            );
            return http.build();
        }
    }

    @Configuration
    @EnableWebSecurity
    static class CustomValidatorConfig {
        @Bean
        public TelegramAuthenticationValidator validator() {
            var mock = mock(TelegramAuthenticationValidator.class);
            doReturn(ValidationResult.valid()).when(mock).validate(any());
            return mock;
        }

        @Bean
        public SecurityFilterChain securityFilterChain(HttpSecurity http) {
            http.with(new TelegramLoginConfigurer<>(), telegram -> telegram
                    .validators(validator())
                    .botToken(BOT_TOKEN)
            );
            return http.build();
        }
    }

    @Configuration
    @EnableWebSecurity
    static class CustomAuthenticationManagerConfig {
        @Bean
        public AuthenticationManager authenticationManager() {
            var mock = mock(AuthenticationManager.class);
            doAnswer(returnsFirstArg()).when(mock).authenticate(any());
            return mock;
        }

        @Bean
        public SecurityFilterChain securityFilterChain(HttpSecurity http) {
            http.with(new TelegramLoginConfigurer<>(), telegram -> telegram
                    .authenticationManager(authenticationManager())
                    .botToken(BOT_TOKEN)
            );
            return http.build();
        }
    }

    @Configuration
    @EnableWebSecurity
    static class CustomAuthenticationConverterConfig {
        @Bean
        public AuthenticationConverter authenticationConverter() {
            var mock = mock(AuthenticationConverter.class);
            when(mock.convert(any())).thenReturn(new TestingAuthenticationToken("user", "pass", "ROLE_USER"));
            return mock;
        }

        @Bean
        public AuthenticationManager authenticationManager() {
            var mock = mock(AuthenticationManager.class);
            doAnswer(returnsFirstArg()).when(mock).authenticate(any());
            return mock;
        }

        @Bean
        public SecurityFilterChain securityFilterChain(HttpSecurity http) {
            http.with(new TelegramLoginConfigurer<>(), telegram -> telegram
                    .botToken(BOT_TOKEN)
                    .authenticationConverter(authenticationConverter())
                    .authenticationManager(authenticationManager())
            );
            return http.build();
        }
    }

    @Configuration
    @EnableWebSecurity
    static class CustomSecurityContextRepositoryConfig {
        @Bean
        public SecurityContextRepository securityContextRepository() {
            return spy(new DelegatingSecurityContextRepository(
                    new RequestAttributeSecurityContextRepository(),
                    new HttpSessionSecurityContextRepository()
            ));
        }

        @Bean
        public SecurityFilterChain securityFilterChain(HttpSecurity http) {
            http.with(new TelegramLoginConfigurer<>(), telegram -> telegram
                    .securityContextRepository(securityContextRepository())
                    .botToken(BOT_TOKEN)
            );
            return http.build();
        }
    }

    @Configuration
    @EnableWebSecurity
    static class CustomAuthenticationDetailsSourceConfig {
        @Bean
        public AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource() {
            return mock();
        }

        @Bean
        public SecurityFilterChain securityFilterChain(HttpSecurity http) {
            http.with(new TelegramLoginConfigurer<>(), telegram -> telegram
                    .authenticationDetailsSource(authenticationDetailsSource())
                    .botToken(BOT_TOKEN)
            );
            return http.build();
        }
    }

    @Configuration
    @EnableWebSecurity
    static class CustomHashValidatorConfig {
        @Bean
        public HashValidator hashValidator() {
            var mock = mock(HashValidator.class);
            doReturn(ValidationResult.valid()).when(mock).validate(any());
            return mock;
        }

        @Bean
        public SecurityFilterChain securityFilterChain(HttpSecurity http) {
            http.with(new TelegramLoginConfigurer<>(), telegram -> telegram
                    .hashValidator(hashValidator())
            );
            return http.build();
        }
    }

    @Configuration
    @EnableWebSecurity
    static class CustomRequestMatcherConfig {
        @Bean
        public SecurityFilterChain securityFilterChain(HttpSecurity http) {
            http.with(new TelegramLoginConfigurer<>(), telegram -> telegram
                    .botToken(BOT_TOKEN)
                    .requestMatcher(pathPattern(HttpMethod.OPTIONS, "/custom/path"))
            );
            return http.build();
        }
    }

    private static String calcHash(Map<String, String> params) throws Exception {
        var dataString = params.entrySet()
                               .stream()
                               .filter(e -> e.getValue() != null)
                               .sorted(Map.Entry.comparingByKey())
                               .map(e -> e.getKey() + "=" + e.getValue())
                               .collect(Collectors.joining("\n"));

        var sha256Digest = MessageDigest.getInstance("SHA-256");

        sha256Digest.update(BOT_TOKEN.getBytes(StandardCharsets.UTF_8));

        var hmac = Mac.getInstance("HmacSHA256");

        hmac.init(new SecretKeySpec(sha256Digest.digest(), "HmacSHA256"));

        hmac.update(dataString.getBytes(StandardCharsets.UTF_8));

        return HexFormat.of().formatHex(hmac.doFinal());
    }

    private static String currentDate() {
        return String.valueOf(Instant.now().getEpochSecond());
    }
}
