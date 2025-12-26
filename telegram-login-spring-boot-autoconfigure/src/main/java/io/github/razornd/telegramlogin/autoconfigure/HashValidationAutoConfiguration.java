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
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;

/**
 * {@link AutoConfiguration @AutoConfiguration} for {@link HashValidator}.
 *
 * @author Daniil Razorenov
 * @see HashValidator
 */
@AutoConfiguration
@EnableConfigurationProperties(TelegramLoginProperties.class)
public class HashValidationAutoConfiguration {

    /**
     * Creates a {@link HashValidator} bean if one is not already present and
     * {@code telegram.login.bot-token} property is set.
     * @param properties the telegram login properties
     * @return a {@link HashValidator} initialized with the bot token
     */
    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "telegram.login", value = "bot-token")
    HashValidator hashValidator(TelegramLoginProperties properties) {
        return new HashValidator(properties.botToken());
    }

}
