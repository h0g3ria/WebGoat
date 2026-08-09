/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.webwolfintroduction;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import jakarta.servlet.http.HttpSession;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.ModelAndView;

/**
 * @author nbaars
 * @since 8/20/17.
 */
@RestController
public class LandingAssignment implements AssignmentEndpoint {
  private static final String RESET_CODE_SESSION_ATTRIBUTE = "webwolfLandingResetCode";
  private static final String RESET_CODE_EXPIRY_SESSION_ATTRIBUTE = "webwolfLandingResetCodeExpiry";
  private static final long RESET_CODE_VALIDITY_SECONDS = 600;

  private final String landingPageUrl;
  private final SecureRandom secureRandom = new SecureRandom();

  public LandingAssignment(@Value("${webwolf.landingpage.url}") String landingPageUrl) {
    this.landingPageUrl = landingPageUrl;
  }

  @PostMapping("/WebWolf/landing")
  @ResponseBody
  public AttackResult click(String uniqueCode, HttpSession session) {
    var expectedCode = session.getAttribute(RESET_CODE_SESSION_ATTRIBUTE);
    var expiresAt = session.getAttribute(RESET_CODE_EXPIRY_SESSION_ATTRIBUTE);
    if (expectedCode instanceof String code
        && expiresAt instanceof Instant expiry
        && expiry.isAfter(Instant.now())
        && code.equals(uniqueCode)) {
      clearResetCode(session);
      return success(this).build();
    }
    return failed(this).feedback("webwolf.landing_wrong").build();
  }

  @GetMapping("/WebWolf/landing/password-reset")
  public ModelAndView openPasswordReset(HttpSession session) {
    var randomBytes = new byte[32];
    secureRandom.nextBytes(randomBytes);
    var uniqueCode = Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);
    session.setAttribute(RESET_CODE_SESSION_ATTRIBUTE, uniqueCode);
    session.setAttribute(
        RESET_CODE_EXPIRY_SESSION_ATTRIBUTE,
        Instant.now().plusSeconds(RESET_CODE_VALIDITY_SECONDS));

    ModelAndView modelAndView = new ModelAndView();
    modelAndView.addObject(
        "webwolfLandingPageUrl", landingPageUrl.replace("//landing", "/landing"));
    modelAndView.addObject("uniqueCode", uniqueCode);

    modelAndView.setViewName("lessons/webwolfintroduction/templates/webwolfPasswordReset.html");
    return modelAndView;
  }

  private void clearResetCode(HttpSession session) {
    session.removeAttribute(RESET_CODE_SESSION_ATTRIBUTE);
    session.removeAttribute(RESET_CODE_EXPIRY_SESSION_ATTRIBUTE);
  }
}
