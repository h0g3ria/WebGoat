/*
 * SPDX-FileCopyrightText: Copyright © 2018 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.passwordreset;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import org.owasp.webgoat.container.CurrentUsername;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

/**
 * @author nbaars
 * @since 8/20/17.
 */
@RestController
public class QuestionsAssignment implements AssignmentEndpoint {

  private static final int MAX_FAILED_ATTEMPTS = 3;
  private static final Duration LOCKOUT_DURATION = Duration.ofMinutes(5);
  private static final Map<String, String> COLORS = new HashMap<>();
  private final Map<String, FailedAttempts> failedAttempts = new HashMap<>();

  static {
    COLORS.put("admin", "green");
    COLORS.put("jerry", "orange");
    COLORS.put("tom", "purple");
    COLORS.put("larry", "yellow");
    COLORS.put("webgoat", "red");
  }

  @PostMapping(
      path = "/PasswordReset/questions",
      consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
  @ResponseBody
  public synchronized AttackResult passwordReset(
      @RequestParam Map<String, Object> json, @CurrentUsername String authenticatedUsername) {
    String securityQuestion = (String) json.getOrDefault("securityQuestion", "");
    String username = (String) json.getOrDefault("username", "");
    String normalizedUsername = username.toLowerCase(Locale.ROOT);
    String attemptKey = authenticatedUsername + '\0' + normalizedUsername;

    if ("webgoat".equals(normalizedUsername)) {
      return failed(this).feedback("password-questions-wrong-user").build();
    }

    String validAnswer = COLORS.get(normalizedUsername);
    if (validAnswer == null) {
      return failed(this)
          .feedback("password-questions-unknown-user")
          .feedbackArgs(username)
          .build();
    }

    Instant now = Instant.now();
    FailedAttempts attempts = failedAttempts.get(attemptKey);
    if (attempts != null) {
      if (attempts.isExpired(now)) {
        failedAttempts.remove(attemptKey);
      } else if (attempts.count() >= MAX_FAILED_ATTEMPTS) {
        return failed(this).build();
      }
    }

    if (validAnswer.equals(securityQuestion)) {
      failedAttempts.remove(attemptKey);
      return success(this).build();
    }
    failedAttempts.compute(
        attemptKey,
        (key, previous) ->
            previous == null ? new FailedAttempts(1, now) : previous.failedAgain(now));
    return failed(this).build();
  }

  private record FailedAttempts(int count, Instant lastFailure) {

    private boolean isExpired(Instant now) {
      return !now.isBefore(lastFailure.plus(LOCKOUT_DURATION));
    }

    private FailedAttempts failedAgain(Instant now) {
      return new FailedAttempts(count + 1, now);
    }
  }
}
