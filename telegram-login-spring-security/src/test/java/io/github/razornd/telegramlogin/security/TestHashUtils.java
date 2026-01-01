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

package io.github.razornd.telegramlogin.security;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.HexFormat;
import java.util.Map;
import java.util.stream.Collectors;

public class TestHashUtils {
    public static String calcHash(String botToken, Map<String, String> params) {
        try {
            var dataString = params.entrySet()
                    .stream()
                    .filter(e -> e.getValue() != null)
                    .sorted(Map.Entry.comparingByKey())
                    .map(e -> e.getKey() + "=" + e.getValue())
                    .collect(Collectors.joining("\n"));

            var sha256Digest = MessageDigest.getInstance("SHA-256");
            sha256Digest.update(botToken.getBytes(StandardCharsets.UTF_8));

            var hmac = Mac.getInstance("HmacSHA256");
            hmac.init(new SecretKeySpec(sha256Digest.digest(), "HmacSHA256"));
            hmac.update(dataString.getBytes(StandardCharsets.UTF_8));

            return HexFormat.of().formatHex(hmac.doFinal());
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new RuntimeException(e);
        }
    }

    public static String currentDate() {
        return String.valueOf(Instant.now().getEpochSecond());
    }
}
