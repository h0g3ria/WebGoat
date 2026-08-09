/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
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
import java.util.regex.Matcher;
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
@AssignmentHints(value = {"SqlStringInjectionHint3-1", "SqlStringInjectionHint3-2"})
public class SqlInjectionLesson3 implements AssignmentEndpoint {

  private static final Pattern UPDATE_QUERY =
      Pattern.compile(
          "\\s*UPDATE\\s+employees\\s+SET\\s+department\\s*=\\s*'((?:''|[^'])*)'"
              + "\\s+WHERE\\s+last_name\\s*=\\s*'((?:''|[^'])*)'\\s*;?\\s*",
          Pattern.CASE_INSENSITIVE);
  private final LessonDataSource dataSource;

  public SqlInjectionLesson3(LessonDataSource dataSource) {
    this.dataSource = dataSource;
  }

  @PostMapping("/SqlInjection/attack3")
  @ResponseBody
  public AttackResult completed(@RequestParam String query) {
    return injectableQuery(query);
  }

  protected AttackResult injectableQuery(String query) {
    Matcher matcher = UPDATE_QUERY.matcher(query);
    if (!matcher.matches()) {
      return failed(this).build();
    }

    String department = matcher.group(1).replace("''", "'");
    String lastName = matcher.group(2).replace("''", "'");
    try (Connection connection = dataSource.getConnection()) {
      try (PreparedStatement statement =
              connection.prepareStatement(
                  "UPDATE employees SET department = ? WHERE last_name = ?");
          PreparedStatement checkStatement =
              connection.prepareStatement(
                  "SELECT * FROM employees WHERE last_name = ?",
                  TYPE_SCROLL_INSENSITIVE,
                  CONCUR_READ_ONLY)) {
        statement.setString(1, department);
        statement.setString(2, lastName);
        statement.executeUpdate();
        checkStatement.setString(1, "Barnett");
        ResultSet results = checkStatement.executeQuery();
        StringBuilder output = new StringBuilder();
        // user completes lesson if the department of Tobi Barnett now is 'Sales'
        results.first();
        if (results.getString("department").equals("Sales")) {
          output.append("<span class='feedback-positive'>" + query + "</span>");
          output.append(SqlInjectionLesson8.generateTable(results));
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
