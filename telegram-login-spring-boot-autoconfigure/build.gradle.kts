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

plugins {
    `java-library`
}

description = "Telegram Login Spring Boot Autoconfigure"

dependencies {
    implementation(project(":telegram-login-spring-security"))
    implementation("org.springframework.boot:spring-boot-autoconfigure")
    implementation("org.springframework.boot:spring-boot-security")

    testImplementation("org.springframework.boot:spring-boot-test")
}

publishing.publications.named<MavenPublication>("maven") {
    pom {
        name = "Telegram Login Spring Boot Autoconfigure"
        description = "Spring Boot autoconfiguration module that provides automatic setup of Telegram Login Widget " +
                "integration with Spring Security, including default validators, converters, and authentication " +
                "providers."
    }
}
