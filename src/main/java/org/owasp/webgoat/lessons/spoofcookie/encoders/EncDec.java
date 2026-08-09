/*
 * SPDX-FileCopyrightText: Copyright © 2021 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.spoofcookie.encoders;

import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.apache.commons.lang3.RandomStringUtils;
import org.springframework.security.crypto.codec.Hex;

/***
 *
 * @author Angel Olle Blazquez
 *
 */

public class EncDec {

  // PoC: weak encoding method

  private static final String HMAC_ALGORITHM = "HmacSHA256";
  private static final String SALT = RandomStringUtils.randomAlphabetic(10);
  private static final byte[] SIGNING_KEY = createSigningKey();

  private EncDec() {}

  public static String encode(final String value) {
    if (value == null) {
      return null;
    }

    String encoded = value.toLowerCase() + SALT;
    encoded = revert(encoded);
    encoded = hexEncode(encoded);
    String payload = base64Encode(encoded);
    return payload + "." + base64Encode(sign(payload));
  }

  public static String decode(final String encodedValue) throws IllegalArgumentException {
    if (encodedValue == null) {
      return null;
    }

    String[] parts = encodedValue.split("\\.", -1);
    if (parts.length != 2
        || !MessageDigest.isEqual(base64DecodeBytes(parts[1]), sign(parts[0]))) {
      throw new IllegalArgumentException("Invalid authentication cookie");
    }

    String decoded = base64Decode(parts[0]);
    decoded = hexDecode(decoded);
    decoded = revert(decoded);
    return decoded.substring(0, decoded.length() - SALT.length());
  }

  private static byte[] createSigningKey() {
    byte[] key = new byte[32];
    new SecureRandom().nextBytes(key);
    return key;
  }

  private static byte[] sign(final String value) {
    try {
      Mac mac = Mac.getInstance(HMAC_ALGORITHM);
      mac.init(new SecretKeySpec(SIGNING_KEY, HMAC_ALGORITHM));
      return mac.doFinal(value.getBytes(StandardCharsets.UTF_8));
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException("HMAC is not available", e);
    } catch (InvalidKeyException e) {
      throw new IllegalStateException("Unable to initialize cookie signing", e);
    }
  }

  private static String revert(final String value) {
    return new StringBuilder(value).reverse().toString();
  }

  private static String hexEncode(final String value) {
    char[] encoded = Hex.encode(value.getBytes(StandardCharsets.UTF_8));
    return new String(encoded);
  }

  private static String hexDecode(final String value) {
    byte[] decoded = Hex.decode(value);
    return new String(decoded);
  }

  private static String base64Encode(final String value) {
    return Base64.getEncoder().encodeToString(value.getBytes());
  }

  private static String base64Encode(final byte[] value) {
    return Base64.getUrlEncoder().withoutPadding().encodeToString(value);
  }

  private static String base64Decode(final String value) {
    byte[] decoded = Base64.getDecoder().decode(value.getBytes());
    return new String(decoded);
  }

  private static byte[] base64DecodeBytes(final String value) {
    return Base64.getUrlDecoder().decode(value);
  }
}
