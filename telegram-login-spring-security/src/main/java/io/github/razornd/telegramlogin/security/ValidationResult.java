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

/**
 * Represents the result of a Telegram authentication validation.
 *
 * <p>Can be either {@link Valid} or {@link Invalid}.
 *
 * @author Daniil Razorenov
 * @see TelegramAuthenticationValidator
 */
sealed public interface ValidationResult permits ValidationResult.Invalid, ValidationResult.Valid {

    /**
     * Successful validation result.
     */
    enum Valid implements ValidationResult {
        /**
         * Singleton instance representing a successful validation result.
         * This instance is used to indicate that validation has passed without errors.
         */
        INSTANCE
    }

    /**
     * Failed validation result with a reason.
     * @param reason the reason for failure
     */
    record Invalid(String reason) implements ValidationResult { }

    /**
     * Factory method for creating a valid result.
     * @return the valid result singleton
     */
    static ValidationResult valid() {
        return Valid.INSTANCE;
    }

    /**
     * Factory method for creating an invalid result.
     * @param reason the reason for failure
     * @return a new invalid result
     */
    static ValidationResult invalid(String reason) {
        return new Invalid(reason);
    }

}
