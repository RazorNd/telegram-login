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
import org.springframework.boot.security.autoconfigure.SecurityAutoConfiguration;
import org.springframework.boot.security.autoconfigure.web.servlet.ServletWebSecurityAutoConfiguration;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

import static org.assertj.core.api.Assertions.assertThat;

class TelegramServletLoginAutoConfigurationTest {

    WebApplicationContextRunner contextRunner = new WebApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(SecurityAutoConfiguration.class,
                                                     HashValidationAutoConfiguration.class,
                                                     TelegramServletLoginAutoConfiguration.class,
                                                     ServletWebSecurityAutoConfiguration.class,
                                                     PropertyPlaceholderAutoConfiguration.class));

    @Test
    void shouldConfigureSecurityFilterChain() {
        contextRunner.withPropertyValues("telegram.login.bot-token=123456")
                     .run(context -> assertThat(context).hasBean("telegramSecurityFilterChain"));
    }

    @Test
    void shouldCreateSecurityFilterChainWithCustomHashValidator() {
        contextRunner.withUserConfiguration(OverrideHashValidatorConfig.class)
                     .run(context -> assertThat(context).hasBean("telegramSecurityFilterChain"));
    }

    @Test
    void shouldBackOffWhenCustomSecurityFilterChainIsPresent() {
        contextRunner.withUserConfiguration(CustomSecurityFilterChainConfig.class)
                     .withPropertyValues("telegram.login.bot-token=123456")
                     .run(context -> {
                         assertThat(context).hasBean("customSecurityFilterChain");
                         assertThat(context).doesNotHaveBean("telegramSecurityFilterChain");
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
    void shouldNotConfigureWhenNotWebApplication() {
        new ApplicationContextRunner()
                .withConfiguration(AutoConfigurations.of(TelegramServletLoginAutoConfiguration.class))
                .withPropertyValues("telegram.login.bot-token=123456")
                .run(context -> assertThat(context).doesNotHaveBean(TelegramServletLoginAutoConfiguration.class));
    }

    @TestConfiguration(proxyBeanMethods = false)
    static class CustomSecurityFilterChainConfig {
        @Bean
        SecurityFilterChain customSecurityFilterChain(HttpSecurity http) {
            return http.build();
        }
    }

}
