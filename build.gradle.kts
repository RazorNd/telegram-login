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

import org.jreleaser.model.Active

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
    id("org.springframework.boot") apply false
    id("org.jreleaser") version "1.22.0"
    java
}

allprojects {
    group = "io.github.razornd.telegramlogin"
    version = "0.2.0"

    repositories {
        mavenCentral()
    }

    plugins.withType<JavaPlugin> {
        the<JavaPluginExtension>().toolchain {
            languageVersion.set(JavaLanguageVersion.of(17))
        }
    }
}

subprojects {
    apply(plugin = "java")

    plugins.withType<JavaLibraryPlugin> {
        apply(plugin = "maven-publish")
        apply(plugin = "signing")

        configure<JavaPluginExtension> {
            withSourcesJar()
            withJavadocJar()
        }

        configure<PublishingExtension> {
            publications {
                create<MavenPublication>("maven") {
                    from(components["java"])
                    pom {
                        name = this@subprojects.name
                        description = this@subprojects.description
                        url = "https://github.com/RazorNd/telegram-login"

                        licenses {
                            license {
                                name = "The Apache License, Version 2.0"
                                url = "https://www.apache.org/licenses/LICENSE-2.0.txt"
                            }
                        }
                        developers {
                            developer {
                                id = "razornd"
                                name = "Daniil Razorenov"
                                email = "razor@razornd.ru"
                            }
                        }
                        scm {
                            connection = "scm:git:https://github.com/RazorNd/telegram-login.git"
                            developerConnection = "scm:git:ssh://git@github.com/RazorNd/telegram-login.git"
                            url = "https://github.com/RazorNd/telegram-login"
                        }
                    }
                }
            }
            repositories {
                maven {
                    name = "Directory"
                    url = uri(layout.buildDirectory.dir("repo/maven"))
                }
            }
        }

        configure<SigningExtension> {
            sign(the<PublishingExtension>().publications["maven"])
        }

        tasks.withType<Javadoc> {
            (options as StandardJavadocDocletOptions).addBooleanOption("html5", true)
        }
    }

    tasks.withType<Test> {
        useJUnitPlatform()
    }

    dependencies {
        val springBootVersion: String by project
        "implementation"(platform("org.springframework.boot:spring-boot-dependencies:$springBootVersion"))
        "testImplementation"("org.springframework.boot:spring-boot-starter-test")
        "testRuntimeOnly"("org.junit.platform:junit-platform-launcher")
    }
}

jreleaser {
    deploy {
        release {
            github {
                changelog {
                    enabled = true
                    links = true
                    formatted = Active.ALWAYS
                }
            }
        }
        maven {
            mavenCentral {
                create(name) {
                    active = Active.RELEASE
                    url = "https://central.sonatype.com/api/v1/publisher"
                    applyMavenCentralRules = true
                    sign = false
                    subprojects {
                        plugins.withType<JavaLibraryPlugin> {
                            stagingRepository(layout.buildDirectory.dir("repo/maven").get().asFile.path)
                        }
                    }
                }
            }
        }
    }
}
