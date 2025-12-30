# Telegram Login for Spring Security

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Version](https://img.shields.io/badge/Version-0.1.0-yellow.svg)](https://github.com/RazorNd/telegram-login)
[![Spring Boot](https://img.shields.io/badge/Spring%20Boot-4.0.1-brightgreen.svg)](https://spring.io/projects/spring-boot)
[![Java](https://img.shields.io/badge/Java-17%2B-orange.svg)](https://www.oracle.com/java/technologies/javase-jdk17-downloads.html)

This project provides seamless integration of the [Telegram Login Widget](https://core.telegram.org/widgets/login) with
Spring Security. It includes a Spring Boot starter for quick setup and a dedicated Spring Security configurer for manual
configuration.

## Features

- **Spring Security Integration**: Native support for Telegram authentication in the Spring Security filter chain.
- **Spring Boot Auto-configuration**: Automatic setup of security filters and validators with minimal configuration.
- **Data Integrity Validation**: Built-in HMAC-SHA256 validation of data received from Telegram.
- **Expiration Check**: Automatic validation of `auth_date` to prevent replay attacks (default 24h).
- **Extensible Architecture**: Custom validators and converters can be easily plugged in. Supports custom
  `TelegramPrincipal` implementations.

## Prerequisites

- Java 17 or higher
- Spring Boot 4.0.1 or higher

## Installation

### Gradle

```kotlin
dependencies {
    implementation("io.github.razornd.telegramlogin:spring-boot-starter-telegram-login:0.1.0")
}
```

### Maven

```xml

<dependency>
    <groupId>io.github.razornd.telegramlogin</groupId>
    <artifactId>spring-boot-starter-telegram-login</artifactId>
    <version>0.1.0</version>
</dependency>
```

## Quick Start (Spring Boot)

1. Add the starter to your project.
2. Configure your Telegram Bot Token in `application.yml`:

   ```yaml
   telegram:
     login:
       bot-token: YOUR_BOT_TOKEN
   ```

3. (Optional) If you have a custom security configuration, you can use `TelegramLoginConfigurer`:

   ```java
   
   @Configuration
   @EnableWebSecurity
   public class SecurityConfig {
   
       @Bean
       public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
           http.authorizeHttpRequests(authorize -> authorize
                       .requestMatchers("/login").permitAll()
                       .anyRequest().authenticated()
               )
               .with(new TelegramLoginConfigurer<>(), telegram -> telegram
                       .botToken("YOUR_BOT_TOKEN")
               )
               .exceptionHandling(ex -> ex.authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login")));
           return http.build();
       }
   }
   ```
4. Add the Telegram Login Widget to your login page:
   ```html
   <script async src="https://telegram.org/js/telegram-widget.js?22" 
        data-telegram-login="<YOUR-BOT-NAME>" 
        data-size="large" 
        data-auth-url="/login/telegram">
   </script>
   ```

## Configuration Properties

The following properties can be used to configure the Telegram Login integration:

| Property                   | Description                                       | Default |
|----------------------------|---------------------------------------------------|---------|
| `telegram.login.bot-token` | Your Telegram Bot token used for hash validation. | -       |

## How it Works

1. The user clicks the Telegram Login Widget on your site.
2. Telegram redirects the user back to your site with authentication data as query parameters (id, first_name,
   last_name, username, photo_url, auth_date, hash).
3. `TelegramAuthenticationConverter` extracts this data and creates a `TelegramAuthenticationToken`, extracting the
   `hash` separately for validation.
4. `TelegramAuthenticationProvider` validates the token:
    - `HashValidator` verifies the HMAC-SHA256 signature using your bot token and the `hash` from the token's
      credentials.
    - `AuthDateExpirationValidator` ensures the data is fresh.
5. If valid, the user is authenticated, and a `TelegramAuthentication` is created containing the `TelegramPrincipal`.

## Samples

Check the [samples/mvc-sample](samples/mvc-sample) directory for a complete working example of a Spring Boot MVC
application with Telegram Login.

## License

This project is licensed under the Apache License, Version 2.0. See the [LICENSE](LICENSE) file for details.

---
Developed by [Daniil Razorenov](https://github.com/razornd)
