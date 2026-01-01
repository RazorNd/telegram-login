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

import java.util.List;
import java.util.stream.Collectors;

/**
 * A {@link TelegramAuthenticationValidator} that delegates validation to a list of other validators.
 *
 * <p>The validation is considered successful if all delegates return a valid result.
 * If one or more delegates return an invalid result, the reasons are combined.
 *
 * @author Daniil Razorenov
 */
public class CompositeTelegramAuthenticationValidator implements TelegramAuthenticationValidator {

    private final List<TelegramAuthenticationValidator> validators;

    /**
     * Creates a new {@link CompositeTelegramAuthenticationValidator} with the given list of validators.
     * @param validators the validators to delegate to
     */
    public CompositeTelegramAuthenticationValidator(List<TelegramAuthenticationValidator> validators) {
        this.validators = validators;
    }

    /**
     * Validates the given token using all delegates.
     * @param token the token to validate
     * @return {@link ValidationResult#valid()} if all delegates return valid results, or
     * a combined {@link ValidationResult#invalid(String)} otherwise
     */
    @Override
    public ValidationResult validate(TelegramAuthenticationToken token) {
        List<ValidationResult.Invalid> invalids = validators.stream()
                .map(validator -> validator.validate(token))
                .filter(ValidationResult.Invalid.class::isInstance)
                .map(ValidationResult.Invalid.class::cast)
                .toList();

        if (invalids.isEmpty()) {
            return ValidationResult.valid();
        }

        String combinedReason = invalids.stream()
                .map(ValidationResult.Invalid::reason)
                .collect(Collectors.joining(", "));

        return ValidationResult.invalid(combinedReason);
    }
}
