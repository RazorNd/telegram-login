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

package io.github.razornd.telegramlogin.autoconfigure;

import io.github.razornd.telegramlogin.autoconfigure.HashValidationAutoConfigurationTest.OverrideHashValidatorConfig;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.autoconfigure.context.PropertyPlaceholderAutoConfiguration;
import org.springframework.boot.security.autoconfigure.web.reactive.ReactiveWebSecurityAutoConfiguration;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.boot.test.context.runner.ReactiveWebApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;

import static org.assertj.core.api.Assertions.assertThat;

class TelegramWebfluxLoginAutoConfigurationTest {

    private final ReactiveWebApplicationContextRunner contextRunner = new ReactiveWebApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(ReactiveWebSecurityAutoConfiguration.class,
                                                     HashValidationAutoConfiguration.class,
                                                     TelegramWebfluxLoginAutoConfiguration.class,
                                                     PropertyPlaceholderAutoConfiguration.class));

    @Test
    void shouldConfigureSecurityFilterChain() {
        contextRunner.withPropertyValues("telegram.login.bot-token=123456")
                     .run(context -> assertThat(context).hasBean("telegramLoginSecurityFilterChain"));
    }

    @Test
    void shouldCreateSecurityFilterChainWithCustomHashValidator() {
        contextRunner.withUserConfiguration(OverrideHashValidatorConfig.class)
                     .run(context -> assertThat(context).hasBean("telegramLoginSecurityFilterChain"));
    }

    @Test
    void shouldBackOffWhenCustomSecurityFilterChainIsPresent() {
        contextRunner.withUserConfiguration(CustomSecurityWebFilterChainConfig.class)
                     .withPropertyValues("telegram.login.bot-token=123456")
                     .run(context -> {
                         assertThat(context).hasBean("customSecurityWebFilterChain");
                         assertThat(context).doesNotHaveBean("telegramLoginSecurityFilterChain");
                     });
    }

    @Test
    void shouldFailWhenBotTokenIsMissing() {
        contextRunner.run(context -> {
            assertThat(context).hasFailed();
            assertThat(context).getFailure()
                               .hasRootCauseInstanceOf(IllegalArgumentException.class)
                               .rootCause()
                               .hasMessage("Bot token or HashValidator must be set");
        });
    }

    @Test
    void shouldNotConfigureWhenNotReactiveWebApplication() {
        new ApplicationContextRunner()
                .withConfiguration(AutoConfigurations.of(TelegramWebfluxLoginAutoConfiguration.class))
                .withPropertyValues("telegram.login.bot-token=123456")
                .run(context -> assertThat(context).doesNotHaveBean(TelegramWebfluxLoginAutoConfiguration.class));
    }

    @TestConfiguration(proxyBeanMethods = false)
    static class CustomSecurityWebFilterChainConfig {
        @Bean
        SecurityWebFilterChain customSecurityWebFilterChain(ServerHttpSecurity http) {
            return http.build();
        }
    }

}
