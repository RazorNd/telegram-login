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

plugins {
    `java-library`
}

dependencies {
    api("org.springframework.boot:spring-boot-starter-security")
    api(project(":telegram-login-spring-security"))
    api(project(":telegram-login-spring-boot-autoconfigure"))
}

publishing.publications.named<MavenPublication>("maven") {
    pom {
        name = "Telegram Login Spring Boot Starter"
        description = "Spring Boot Starter for integrating Telegram Login Widget with Spring Security, providing " +
                "auto-configuration and seamless authentication setup"
    }
}
