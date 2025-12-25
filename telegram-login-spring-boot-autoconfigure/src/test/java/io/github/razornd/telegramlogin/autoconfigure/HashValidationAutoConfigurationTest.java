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

package io.github.razornd.telegramlogin.autoconfigure;

import io.github.razornd.telegramlogin.security.HashValidator;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Bean;

import static org.assertj.core.api.Assertions.assertThat;

class HashValidationAutoConfigurationTest {

    ApplicationContextRunner contextRunner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(HashValidationAutoConfiguration.class));


    @Test
    void shouldCreateHashValidatorIfPropertySet() {
        contextRunner.withPropertyValues("telegram.login.bot-token=1551731753")
                     .run(context -> assertThat(context).hasSingleBean(HashValidator.class));
    }

    @Test
    void shouldNotCreateHashValidatorIfPropertyNotSet() {
        contextRunner.run(context -> assertThat(context).doesNotHaveBean(HashValidator.class));
    }

    @Test
    void shouldUseOverrideHashValidator() {
        contextRunner.withUserConfiguration(OverrideHashValidatorConfig.class)
                     .withPropertyValues("telegram.login.bot-token=1551731753")
                     .run(context -> {
                         assertThat(context).hasBean("overrideHashValidator");
                         assertThat(context).doesNotHaveBean("hashValidator");
                     });
    }

    @TestConfiguration(proxyBeanMethods = false)
    static class OverrideHashValidatorConfig {
        @Bean
        HashValidator overrideHashValidator() {
            return new HashValidator(new byte[0]);
        }
    }
}
