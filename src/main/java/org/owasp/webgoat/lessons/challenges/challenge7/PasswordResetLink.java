/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.challenges.challenge7;

import java.security.SecureRandom;
import java.util.Base64;

/**
 * @author nbaars
 * @since 8/17/17.
 */
public class PasswordResetLink {

  private static final SecureRandom SECURE_RANDOM = new SecureRandom();

  public String createPasswordReset() {
    byte[] token = new byte[32];
    SECURE_RANDOM.nextBytes(token);
    return Base64.getUrlEncoder().withoutPadding().encodeToString(token);
  }
}
