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

import io.github.razornd.telegramlogin.security.config.TelegramLoginConfigurer;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication.Type;
import org.springframework.boot.security.autoconfigure.web.servlet.ConditionalOnDefaultWebSecurity;
import org.springframework.boot.security.autoconfigure.web.servlet.ServletWebSecurityAutoConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;

/**
 * {@link AutoConfiguration @AutoConfiguration} for Telegram Login in a Servlet-based web application.
 *
 * <p>Configures a {@link SecurityFilterChain} if the default web security is missing.
 *
 * @author Daniil Razorenov
 * @see TelegramLoginConfigurer
 */
@AutoConfiguration(before = ServletWebSecurityAutoConfiguration.class,
                   after = HashValidationAutoConfiguration.class,
                   afterName = "org.springframework.boot.webmvc.autoconfigure.WebMvcAutoConfiguration")
@ConditionalOnClass(EnableWebSecurity.class)
@ConditionalOnWebApplication(type = Type.SERVLET)
public class TelegramServletLoginAutoConfiguration {

    @Configuration(proxyBeanMethods = false)
    @ConditionalOnDefaultWebSecurity
    static class SecurityFilterChainConfiguration {

        /**
         * Creates a default {@link SecurityFilterChain} configured with {@link TelegramLoginConfigurer}.
         * @param http the {@link HttpSecurity} to configure
         * @return the configured {@link SecurityFilterChain}
         */
        @Bean
        SecurityFilterChain telegramSecurityFilterChain(HttpSecurity http) {
            http.authorizeHttpRequests(requests -> {
                    requests.requestMatchers("/login", "/error").permitAll();
                    requests.anyRequest().authenticated();
                })
                .with(new TelegramLoginConfigurer<>())
                .exceptionHandling(ex -> ex.authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login")));

            return http.build();
        }

    }
}
