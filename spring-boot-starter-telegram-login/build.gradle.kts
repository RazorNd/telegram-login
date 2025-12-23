plugins {
    `java-library`
}

dependencies {
    api("org.springframework.boot:spring-boot-starter-security")
    api(project(":telegram-login-spring-security"))
}
