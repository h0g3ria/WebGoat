/*
 * SPDX-FileCopyrightText: Copyright © 2018 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.sqlinjection.introduction;

import static java.sql.ResultSet.CONCUR_READ_ONLY;
import static java.sql.ResultSet.TYPE_SCROLL_INSENSITIVE;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.regex.Pattern;
import org.owasp.webgoat.container.LessonDataSource;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@AssignmentHints(
    value = {"SqlStringInjectionHint4-1", "SqlStringInjectionHint4-2", "SqlStringInjectionHint4-3"})
public class SqlInjectionLesson4 implements AssignmentEndpoint {

  private static final Pattern ADD_PHONE_COLUMN =
      Pattern.compile(
          "\\s*ALTER\\s+TABLE\\s+employees\\s+ADD(?:\\s+COLUMN)?\\s+phone"
              + "\\s+VARCHAR\\s*\\(\\s*20\\s*\\)\\s*;?\\s*",
          Pattern.CASE_INSENSITIVE);
  private static final String ADD_PHONE_COLUMN_SQL =
      "ALTER TABLE employees ADD COLUMN phone VARCHAR(20)";
  private static final String SELECT_PHONE_SQL = "SELECT phone FROM employees";

  private final LessonDataSource dataSource;

  public SqlInjectionLesson4(LessonDataSource dataSource) {
    this.dataSource = dataSource;
  }

  @PostMapping("/SqlInjection/attack4")
  @ResponseBody
  public AttackResult completed(@RequestParam String query) {
    return injectableQuery(query);
  }

  protected AttackResult injectableQuery(String query) {
    if (!ADD_PHONE_COLUMN.matcher(query).matches()) {
      return failed(this).build();
    }

    try (Connection connection = dataSource.getConnection()) {
      try (PreparedStatement alterTable = connection.prepareStatement(ADD_PHONE_COLUMN_SQL);
          PreparedStatement selectPhone =
              connection.prepareStatement(
                  SELECT_PHONE_SQL, TYPE_SCROLL_INSENSITIVE, CONCUR_READ_ONLY)) {
        alterTable.executeUpdate();
        connection.commit();
        ResultSet results = selectPhone.executeQuery();
        StringBuilder output = new StringBuilder();
        // user completes lesson if column phone exists
        if (results.first()) {
          output.append("<span class='feedback-positive'>" + query + "</span>");
          return success(this).output(output.toString()).build();
        } else {
          return failed(this).output(output.toString()).build();
        }
      } catch (SQLException sqle) {
        return failed(this).output(sqle.getMessage()).build();
      }
    } catch (Exception e) {
      return failed(this).output(this.getClass().getName() + " : " + e.getMessage()).build();
    }
  }
}
