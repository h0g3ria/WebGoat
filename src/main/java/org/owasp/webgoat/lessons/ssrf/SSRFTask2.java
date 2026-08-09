/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.ssrf;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@AssignmentHints({"ssrf.hint3"})
public class SSRFTask2 implements AssignmentEndpoint {

  private static final String ALLOWED_HOST = "ifconfig.pro";
  private static final String ALLOWED_URL = "http://" + ALLOWED_HOST;

  @PostMapping("/SSRF/task2")
  @ResponseBody
  public AttackResult completed(@RequestParam String url) {
    return furBall(url);
  }

  protected AttackResult furBall(String url) {
    if (ALLOWED_URL.equals(url)) {
      String html;
      try (InputStream in = openAllowedConnection()) {
        html =
            new String(in.readAllBytes(), StandardCharsets.UTF_8)
                .replaceAll("\n", "<br>"); // Otherwise the \n gets escaped in the response
      } catch (MalformedURLException e) {
        return getFailedResult(e.getMessage());
      } catch (IOException e) {
        // in case the external site is down, the test and lesson should still be ok
        html =
            "<html><body>Although the http://ifconfig.pro site is down, you still managed to solve"
                + " this exercise the right way!</body></html>";
      }
      return success(this).feedback("ssrf.success").output(html).build();
    }
    var html = "<img class=\"image\" alt=\"image post\" src=\"images/cat.jpg\">";
    return getFailedResult(html);
  }

  private InputStream openAllowedConnection() throws IOException {
    for (InetAddress address : InetAddress.getAllByName(ALLOWED_HOST)) {
      if (address.isAnyLocalAddress()
          || address.isLoopbackAddress()
          || address.isLinkLocalAddress()
          || address.isSiteLocalAddress()
          || address.isMulticastAddress()) {
        throw new IOException("The configured host resolves to a non-public address");
      }
    }

    HttpURLConnection connection = (HttpURLConnection) new URL(ALLOWED_URL).openConnection();
    connection.setInstanceFollowRedirects(false);
    int status = connection.getResponseCode();
    if (status >= 300 && status < 400) {
      connection.disconnect();
      throw new IOException("Redirects are not allowed");
    }
    return connection.getInputStream();
  }

  private AttackResult getFailedResult(String errorMsg) {
    return failed(this).feedback("ssrf.failure").output(errorMsg).build();
  }
}
