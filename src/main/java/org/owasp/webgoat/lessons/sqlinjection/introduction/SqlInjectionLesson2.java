/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.sqlinjection.introduction;

import static java.sql.ResultSet.CONCUR_READ_ONLY;
import static java.sql.ResultSet.TYPE_SCROLL_INSENSITIVE;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

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
    value = {
      "SqlStringInjectionHint2-1",
      "SqlStringInjectionHint2-2",
      "SqlStringInjectionHint2-3",
      "SqlStringInjectionHint2-4"
    })
public class SqlInjectionLesson2 implements AssignmentEndpoint {

  private static final Pattern DEPARTMENT_LOOKUP =
      Pattern.compile(
          "^\\s*select\\s+department\\s+from\\s+employees\\s+where\\s+(?:"
              + "userid\\s*=\\s*(\\d+)"
              + "|first_name\\s*=\\s*'([^']*)'\\s+and\\s+last_name\\s*=\\s*'([^']*)'"
              + "|last_name\\s*=\\s*'([^']*)'\\s+and\\s+first_name\\s*=\\s*'([^']*)')"
              + "\\s*;?\\s*$",
          Pattern.CASE_INSENSITIVE);

  private final LessonDataSource dataSource;

  public SqlInjectionLesson2(LessonDataSource dataSource) {
    this.dataSource = dataSource;
  }

  @PostMapping("/SqlInjection/attack2")
  @ResponseBody
  public AttackResult completed(@RequestParam String query) {
    return injectableQuery(query);
  }

  protected AttackResult injectableQuery(String query) {
    var lookup = DEPARTMENT_LOOKUP.matcher(query);
    if (!lookup.matches()) {
      return failed(this).feedback("sql-injection.2.failed").build();
    }

    try (var connection = dataSource.getConnection()) {
      String sql;
      if (lookup.group(1) != null) {
        sql = "SELECT department FROM employees WHERE userid = ?";
      } else {
        sql = "SELECT department FROM employees WHERE first_name = ? AND last_name = ?";
      }

      try (PreparedStatement statement =
          connection.prepareStatement(sql, TYPE_SCROLL_INSENSITIVE, CONCUR_READ_ONLY)) {
        if (lookup.group(1) != null) {
          statement.setString(1, lookup.group(1));
        } else if (lookup.group(2) != null) {
          statement.setString(1, lookup.group(2));
          statement.setString(2, lookup.group(3));
        } else {
          statement.setString(1, lookup.group(5));
          statement.setString(2, lookup.group(4));
        }

        try (ResultSet results = statement.executeQuery()) {
          StringBuilder output = new StringBuilder();

          if (!results.first()) {
            return failed(this).feedback("sql-injection.2.failed").output(output.toString()).build();
          }

          if (results.getString("department").equals("Marketing")) {
            output.append("<span class='feedback-positive'>" + query + "</span>");
            output.append(SqlInjectionLesson8.generateTable(results));
            return success(this)
                .feedback("sql-injection.2.success")
                .output(output.toString())
                .build();
          } else {
            return failed(this)
                .feedback("sql-injection.2.failed")
                .output(output.toString())
                .build();
          }
        }
      }
    } catch (SQLException sqle) {
      return failed(this).feedback("sql-injection.2.failed").output(sqle.getMessage()).build();
    }
  }
}
