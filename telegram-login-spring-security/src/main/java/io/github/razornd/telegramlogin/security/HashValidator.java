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

package io.github.razornd.telegramlogin.security;

import org.jspecify.annotations.Nullable;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.Optional;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class HashValidator implements TelegramAuthenticationValidator {

    private static final String HMAC_ALGORITHM = "HmacSHA256";
    private static final String HASH_ALGORITHM = "SHA-256";

    private static final HexFormat HEX_FORMAT = HexFormat.of();

    private final byte[] secretKey;

    public HashValidator(String botToken) {
        secretKey = sha256(botToken);
    }

    @Override
    public ValidationResult validate(TelegramAuthenticationToken token) {
        var telegramUser = token.getPrincipal();

        return parseHash(telegramUser.hash())
                .map(hash -> validateUserHash(telegramUser, hash))
                .orElseGet(() -> ValidationResult.invalid("Invalid hash format"));
    }

    private ValidationResult validateUserHash(TelegramUser telegramUser, byte[] hash) {
        var dataCheckString = makeDataCheckString(telegramUser);

        var hmac = hmac(dataCheckString);

        if (MessageDigest.isEqual(hmac, hash)) {
            return ValidationResult.valid();
        }

        return ValidationResult.invalid("Invalid hash");
    }

    private Optional<byte[]> parseHash(String hash) {
        try {
            return Optional.of(HEX_FORMAT.parseHex(hash));
        } catch (IllegalArgumentException e) {
            return Optional.empty();
        }
    }

    private String makeDataCheckString(TelegramUser telegramUser) {
        return Stream.of(new DataPart("id", String.valueOf(telegramUser.id())),
                         new DataPart("first_name", telegramUser.firstName()),
                         new DataPart("last_name", telegramUser.lastName()),
                         new DataPart("username", telegramUser.username()),
                         new DataPart("photo_url", telegramUser.photoUrl()),
                         new DataPart("auth_date", String.valueOf(telegramUser.authDate().getEpochSecond())))
                     .filter(DataPart::hasValue)
                     .sorted(Comparator.comparing(DataPart::name))
                     .map(DataPart::toString)
                     .collect(Collectors.joining("\n"));
    }

    private byte[] hmac(String dataCheckString) {
        try {
            var hmac = Mac.getInstance(HMAC_ALGORITHM);

            hmac.init(new SecretKeySpec(secretKey, HMAC_ALGORITHM));

            return hmac.doFinal(dataCheckString.getBytes(StandardCharsets.UTF_8));
        } catch (NoSuchAlgorithmException | InvalidKeyException exception) {
            throw new IllegalStateException(exception);
        }
    }

    private byte[] sha256(String botToken) {
        try {
            return MessageDigest.getInstance(HASH_ALGORITHM).digest(botToken.getBytes(StandardCharsets.UTF_8));
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException(exception);
        }
    }

    private record DataPart(String name, @Nullable String value) {

        boolean hasValue() {
            return value != null;
        }

        @Override
        public String toString() {
            return name + "=" + value;
        }
    }
}
