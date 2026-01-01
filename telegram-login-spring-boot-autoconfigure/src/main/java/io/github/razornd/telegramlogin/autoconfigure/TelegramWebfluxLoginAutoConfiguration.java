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

import io.github.razornd.telegramlogin.security.HashValidator;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.security.autoconfigure.web.reactive.ReactiveWebSecurityAutoConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.authentication.RedirectServerAuthenticationEntryPoint;

import static io.github.razornd.telegramlogin.security.config.TelegramLoginServerSecurityConfigurer.telegramLogin;

@AutoConfiguration(before = ReactiveWebSecurityAutoConfiguration.class,
                   after = HashValidationAutoConfiguration.class,
                   afterName = "org.springframework.boot.webflux.autoconfigure.WebFluxAutoConfiguration")
@ConditionalOnClass(EnableWebFluxSecurity.class)
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.REACTIVE)
@EnableConfigurationProperties(TelegramLoginProperties.class)
public class TelegramWebfluxLoginAutoConfiguration {

    @Configuration(proxyBeanMethods = false)
    @ConditionalOnMissingBean(SecurityWebFilterChain.class)
    static class TelegramWebfluxLoginConfiguration {
        @Bean
        SecurityWebFilterChain telegramLoginSecurityFilterChain(ServerHttpSecurity http,
                                                                ObjectProvider<HashValidator> hashValidator) {
            telegramLogin(http, telegram -> hashValidator.ifAvailable(telegram::hashValidator));

            http.authorizeExchange(exchange -> {
                exchange.pathMatchers("/login").permitAll();
                exchange.anyExchange().authenticated();
            });

            var entryPoint = new RedirectServerAuthenticationEntryPoint("/login");
            http.exceptionHandling(handling -> handling.authenticationEntryPoint(entryPoint));

            return http.build();
        }
    }

}
