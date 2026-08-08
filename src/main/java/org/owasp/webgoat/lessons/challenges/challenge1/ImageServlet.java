/*
 * SPDX-FileCopyrightText: Copyright © 2020 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.challenges.challenge1;

import static org.springframework.web.bind.annotation.RequestMethod.GET;
import static org.springframework.web.bind.annotation.RequestMethod.POST;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.SecureRandom;
import javax.imageio.ImageIO;
import org.springframework.core.io.ClassPathResource;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ImageServlet {

  public static final int PINCODE = new SecureRandom().nextInt(10000);

  @RequestMapping(
      method = {GET, POST},
      value = "/challenge/logo",
      produces = MediaType.IMAGE_PNG_VALUE)
  @ResponseBody
  public byte[] logo() throws IOException {
    var resource = new ClassPathResource("lessons/challenges/images/webgoat2.png");
    try (var input = resource.getInputStream(); var output = new ByteArrayOutputStream()) {
      var image = ImageIO.read(input);
      if (image == null || !ImageIO.write(image, "png", output)) {
        throw new IOException("Unable to decode challenge logo");
      }
      return output.toByteArray();
    }
  }
}
