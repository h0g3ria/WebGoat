/*
 * SPDX-FileCopyrightText: Copyright © 2018 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.passwordreset;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.context.annotation.SessionScope;

/**
 * @author nbaars
 * @since 8/20/17.
 */
@RestController
public class QuestionsAssignment implements AssignmentEndpoint {

  private static final int MAX_ATTEMPTS = 3;
  private static final Map<String, String> COLORS = new HashMap<>();
  private final QuestionAttempts questionAttempts;

  static {
    COLORS.put("admin", "green");
    COLORS.put("jerry", "orange");
    COLORS.put("tom", "purple");
    COLORS.put("larry", "yellow");
    COLORS.put("webgoat", "red");
  }

  public QuestionsAssignment(QuestionAttempts questionAttempts) {
    this.questionAttempts = questionAttempts;
  }

  @PostMapping(
      path = "/PasswordReset/questions",
      consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
  @ResponseBody
  public AttackResult passwordReset(@RequestParam Map<String, Object> json) {
    String securityQuestion = (String) json.getOrDefault("securityQuestion", "");
    String username = (String) json.getOrDefault("username", "");
    String normalizedUsername = username.toLowerCase(Locale.ROOT);

    if ("webgoat".equalsIgnoreCase(normalizedUsername)) {
      return failed(this).feedback("password-questions-wrong-user").build();
    }

    String validAnswer = COLORS.get(normalizedUsername);
    if (validAnswer == null) {
      return failed(this)
          .feedback("password-questions-unknown-user")
          .feedbackArgs(username)
          .build();
    } else if (questionAttempts.verify(normalizedUsername, validAnswer, securityQuestion)) {
      return success(this).build();
    }
    return failed(this).build();
  }

  @Component
  @SessionScope
  static class QuestionAttempts {

    private final Map<String, Integer> failedAttempts = new HashMap<>();

    synchronized boolean verify(String username, String validAnswer, String submittedAnswer) {
      if (failedAttempts.getOrDefault(username, 0) >= MAX_ATTEMPTS) {
        return false;
      }
      if (validAnswer.equals(submittedAnswer)) {
        return true;
      }
      failedAttempts.merge(username, 1, Integer::sum);
      return false;
    }
  }
}
