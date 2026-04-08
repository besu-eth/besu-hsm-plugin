/*
 * Copyright contributors to Besu.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package org.hyperledger.besu.plugin.services.securitymodule.hsm;

import org.hyperledger.besu.plugin.services.securitymodule.SecurityModuleException;

/** Package-private validation utilities that throw {@link SecurityModuleException} on failure. */
final class Validations {

  private Validations() {}

  /**
   * Validates that the given string is neither {@code null} nor blank.
   *
   * @param value the string to validate
   * @param message the exception message if validation fails
   * @return the validated string
   * @throws SecurityModuleException if {@code value} is null or blank
   */
  static String requireNonBlank(final String value, final String message) {
    if (value == null || value.isBlank()) {
      throw new SecurityModuleException(message);
    }
    return value;
  }

  /**
   * Validates that the given object is not {@code null}.
   *
   * @param <T> the type of the object
   * @param value the object to validate
   * @param message the exception message if validation fails
   * @return the validated object
   * @throws SecurityModuleException if {@code value} is null
   */
  static <T> T requireNonNull(final T value, final String message) {
    if (value == null) {
      throw new SecurityModuleException(message);
    }
    return value;
  }
}
