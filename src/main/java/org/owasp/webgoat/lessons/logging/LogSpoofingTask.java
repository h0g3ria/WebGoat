/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.logging;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import org.apache.logging.log4j.util.Strings;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class LogSpoofingTask implements AssignmentEndpoint {

  @PostMapping("/LogSpoofing/log-spoofing")
  @ResponseBody
  public AttackResult completed(@RequestParam String username, @RequestParam String password) {
    if (Strings.isEmpty(username)) {
      return failed(this).output(username).build();
    }
    String logOutput = username.replace('\r', '_').replace('\n', '_');
    if (username.contains("<p>") || username.contains("<div>")) {
      return failed(this).output("Try to think of something simple ").build();
    }
    int carriageReturn = username.indexOf('\r');
    int lineFeed = username.indexOf('\n');
    int lineBreak =
        carriageReturn < 0
            ? lineFeed
            : lineFeed < 0 ? carriageReturn : Math.min(carriageReturn, lineFeed);
    if (lineBreak >= 0 && lineBreak < username.indexOf("admin")) {
      return success(this).output(logOutput).build();
    }
    return failed(this).output(logOutput).build();
  }
}
