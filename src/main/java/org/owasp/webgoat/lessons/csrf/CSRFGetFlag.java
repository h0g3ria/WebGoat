/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.csrf;

import jakarta.servlet.http.HttpServletRequest;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;
import org.owasp.webgoat.container.i18n.PluginMessages;
import org.owasp.webgoat.container.session.LessonSession;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

/** Created by jason on 9/30/17. */
@RestController
public class CSRFGetFlag {

  private static final SecureRandom RANDOM = new SecureRandom();

  @Autowired LessonSession userSessionData;
  @Autowired private PluginMessages pluginMessages;

  @PostMapping(
      path = "/csrf/basic-get-flag",
      produces = {"application/json"})
  @ResponseBody
  public Map<String, Object> invoke(HttpServletRequest req) {

    Map<String, Object> response = new HashMap<>();

    if (!isSameOrigin(req)) {
      response.put("success", false);
      response.put("message", "The request origin could not be verified");
      response.put("flag", null);
      return response;
    }

    userSessionData.setValue("csrf-get-success", RANDOM.nextInt(65536));
    response.put("success", true);
    response.put("message", pluginMessages.getMessage("csrf-get-null-referer.success"));
    response.put("flag", userSessionData.getValue("csrf-get-success"));
    return response;
  }

  private boolean isSameOrigin(HttpServletRequest request) {
    String source = request.getHeader("Origin");
    if (source == null) {
      source = request.getHeader("Referer");
    }
    if (source == null || "null".equals(source)) {
      return false;
    }

    try {
      URI sourceUri = new URI(source);
      return request.getScheme().equalsIgnoreCase(sourceUri.getScheme())
          && request.getServerName().equalsIgnoreCase(sourceUri.getHost())
          && effectivePort(request.getScheme(), request.getServerPort())
              == effectivePort(sourceUri.getScheme(), sourceUri.getPort());
    } catch (URISyntaxException | NullPointerException e) {
      return false;
    }
  }

  private int effectivePort(String scheme, int port) {
    if (port != -1) {
      return port;
    }
    return "https".equalsIgnoreCase(scheme) ? 443 : 80;
  }
}
