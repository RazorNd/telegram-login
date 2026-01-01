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

package io.github.razornd.telegramlogin.sample.mvc;

import org.htmlunit.WebClient;
import org.htmlunit.html.HtmlPage;
import org.junit.jupiter.api.Test;
import org.springframework.boot.resttestclient.autoconfigure.AutoConfigureRestTestClient;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.test.web.htmlunit.UriBuilderFactoryWebClient;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.web.util.DefaultUriBuilderFactory;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.HexFormat;
import java.util.Map;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;

@AutoConfigureRestTestClient
@SpringBootTest(properties = "telegram.login.bot-token=test-bot-token", webEnvironment = WebEnvironment.RANDOM_PORT)
class SampleApplicationTests {

    @LocalServerPort
    int port;

    @Test
    void unauthorizedRedirectsToLogin() throws IOException {
        try (var client = createClient()) {
            var page = client.getPage("/");

            assertThat(page.getUrl()).hasPath("/login");
        }
    }

    @Test
    void loginAndCheckHomePage() throws IOException {
        var date = String.valueOf(Instant.now().getEpochSecond());

        var hash = calcHash(Map.of("id", "123",
                                   "first_name", "Test",
                                   "username", "testuser",
                                   "auth_date", date));

        String loginUrl = "/login/telegram" +
                          "?id=123" +
                          "&first_name=Test" +
                          "&username=testuser" +
                          "&auth_date=" + date +
                          "&hash=" + hash;

        try (var client = createClient()) {
            HtmlPage homePage = client.getPage(loginUrl);

            assertThat(homePage.getUrl().getPath()).isEqualTo("/");
            assertThat(homePage.getBody().asNormalizedText()).contains("Welcome, Test!");
        }
    }

    static String calcHash(Map<String, String> params) {
        var data = params.entrySet()
                         .stream()
                         .sorted(Map.Entry.comparingByKey())
                         .map(e -> e.getKey() + "=" + e.getValue())
                         .collect(Collectors.joining("\n"));

        try {
            var secretKey = MessageDigest.getInstance("SHA-256")
                                         .digest("test-bot-token".getBytes(StandardCharsets.UTF_8));

            var hmac = Mac.getInstance("HmacSHA256");

            hmac.init(new SecretKeySpec(secretKey, "HmacSHA256"));

            hmac.update(data.getBytes(StandardCharsets.UTF_8));

            return HexFormat.of().formatHex(hmac.doFinal());
        } catch (Exception e) {
            throw new IllegalStateException("Can't calculate hash", e);
        }
    }

    private WebClient createClient() {
        var uriFactory = new DefaultUriBuilderFactory("http://localhost:%d".formatted(port));
        var webClient = new UriBuilderFactoryWebClient(uriFactory);
        webClient.getOptions().setJavaScriptEnabled(false);
        return webClient;
    }
}
