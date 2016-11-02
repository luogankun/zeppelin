/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.zeppelin.realm;

import org.apache.shiro.authc.*;
import org.apache.shiro.authz.AuthorizationException;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.config.ConfigurationException;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.util.ByteSource;
import org.apache.shiro.util.JdbcUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.Set;


/**
 * Custom Realm
 */
public class KsRealm extends AuthorizingRealm {
  protected static final String DEFAULT_AUTHENTICATION_QUERY
    = "SELECT password FROM sec_user WHERE user_name = ?";

  protected static final String DEFAULT_SALTED_AUTHENTICATION_QUERY
    = "select password, password_salt from sec_user where user_name = ?";

  protected static final String DEFAULT_USER_ROLES_QUERY
    = "SELECT role_name from sec_user_role left join sec_role using(role_id) left " +
    "join sec_user using(user_id) WHERE user_name = ?";

  protected static final String DEFAULT_PERMISSIONS_QUERY
    = "SELECT permission_name FROM sec_role_permission left " +
    "join sec_role using(role_id) left join sec_permission " +
    "using(permission_id) WHERE role_name = ?";

  private static final Logger log = LoggerFactory.getLogger(KsRealm.class);

  /**
   *
   */
  public enum SaltStyle {
    NO_SALT, CRYPT, COLUMN, EXTERNAL
  }

  ;

  private DataSource dataSource;

  private String authenticationQuery = DEFAULT_AUTHENTICATION_QUERY;

  private String userRolesQuery = DEFAULT_USER_ROLES_QUERY;

  private String permissionsQuery = DEFAULT_PERMISSIONS_QUERY;

  private boolean permissionsLookupEnabled = false;

  private SaltStyle saltStyle = SaltStyle.NO_SALT;

  public void setDataSource(DataSource dataSource) {
    this.dataSource = dataSource;
  }

  public void setAuthenticationQuery(String authenticationQuery) {
    this.authenticationQuery = authenticationQuery;
  }

  public void setUserRolesQuery(String userRolesQuery) {
    this.userRolesQuery = userRolesQuery;
  }

  public void setPermissionsQuery(String permissionsQuery) {
    this.permissionsQuery = permissionsQuery;
  }

  public void setPermissionsLookupEnabled(boolean permissionsLookupEnabled) {
    this.permissionsLookupEnabled = permissionsLookupEnabled;
  }

  public void setSaltStyle(SaltStyle saltStyle) {
    this.saltStyle = saltStyle;
    if (saltStyle == SaltStyle.COLUMN && authenticationQuery.equals(DEFAULT_AUTHENTICATION_QUERY)) {
      authenticationQuery = DEFAULT_SALTED_AUTHENTICATION_QUERY;
    }
  }

  public AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token)
      throws AuthenticationException {

    UsernamePasswordToken upToken = (UsernamePasswordToken) token;
    String username = upToken.getUsername();

    // Null username is invalid
    if (username == null) {
      throw new AccountException("Null usernames are not allowed by this realm.");
    }

    Connection conn = null;
    SimpleAuthenticationInfo info = null;
    try {
      conn = dataSource.getConnection();

      String password = null;
      String salt = null;
      switch (saltStyle) {
          case NO_SALT:
            password = getPasswordForUser(conn, username)[0];
            break;
          case CRYPT:
            throw new ConfigurationException("Not implemented yet");
          //break;
          case COLUMN:
            String[] queryResults = getPasswordForUser(conn, username);
            password = queryResults[0];
            salt = queryResults[1];
            break;
          case EXTERNAL:
            password = getPasswordForUser(conn, username)[0];
            salt = getSaltForUser(username);
      }

      if (password == null) {
        throw new UnknownAccountException("No account found for user [" + username + "]");
      }

      info = new SimpleAuthenticationInfo(username, password.toCharArray(), getName());

      if (salt != null) {
        info.setCredentialsSalt(ByteSource.Util.bytes(salt));
      }

    } catch (SQLException e) {
      final String message = "There was a SQL error while authenticating user [" + username + "]";
      if (log.isErrorEnabled()) {
        log.error(message, e);
      }

      // Rethrow any SQL errors as an authentication exception
      throw new AuthenticationException(message, e);
    } finally {
      JdbcUtils.closeConnection(conn);
    }

    return info;
  }

  public String[] getPasswordForUser(Connection conn, String username) throws SQLException {

    String[] result;
    boolean returningSeparatedSalt = false;
    switch (saltStyle) {
        case NO_SALT:
        case CRYPT:
        case EXTERNAL:
          result = new String[1];
          break;
        default:
          result = new String[2];
          returningSeparatedSalt = true;
    }

    PreparedStatement ps = null;
    ResultSet rs = null;
    try {
      ps = conn.prepareStatement(authenticationQuery);
      ps.setString(1, username);

      // Execute query
      rs = ps.executeQuery();

      boolean foundResult = false;
      while (rs.next()) {

        // Check to ensure only one row is processed
        if (foundResult) {
          throw new AuthenticationException("More than one user row found for user " +
            "[" + username + "]. Usernames must be unique.");
        }

        result[0] = rs.getString(1);
        if (returningSeparatedSalt) {
          result[1] = rs.getString(2);
        }

        foundResult = true;
      }
    } finally {
      JdbcUtils.closeResultSet(rs);
      JdbcUtils.closeStatement(ps);
    }

    return result;
  }

  @Override
  public AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {

    //null usernames are invalid
    if (principals == null) {
      throw new AuthorizationException("PrincipalCollection method argument cannot be null.");
    }

    String username = (String) getAvailablePrincipal(principals);

    Connection conn = null;
    Set<String> roleNames = null;
    Set<String> permissions = null;
    try {
      conn = dataSource.getConnection();

      // Retrieve roles and permissions from database
      roleNames = getRoleNamesForUser(conn, username);
      if (permissionsLookupEnabled) {
        permissions = getPermissions(conn, username, roleNames);
      }

    } catch (SQLException e) {
      final String message = "There was a SQL error while authorizing user [" + username + "]";
      if (log.isErrorEnabled()) {
        log.error(message, e);
      }

      // Rethrow any SQL errors as an authorization exception
      throw new AuthorizationException(message, e);
    } finally {
      JdbcUtils.closeConnection(conn);
    }

    SimpleAuthorizationInfo info = new SimpleAuthorizationInfo(roleNames);
    info.setStringPermissions(permissions);
    return info;

  }

  public Set<String> getRoleNamesForUser(Connection conn, String username) throws SQLException {
    PreparedStatement ps = null;
    ResultSet rs = null;
    Set<String> roleNames = new LinkedHashSet<String>();
    try {
      ps = conn.prepareStatement(userRolesQuery);
      ps.setString(1, username);

      // Execute query
      rs = ps.executeQuery();

      // Loop over results and add each returned role to a set
      while (rs.next()) {

        String roleName = rs.getString(1);

        // Add the role to the list of names if it isn't null
        if (roleName != null) {
          roleNames.add(roleName);
        } else {
          if (log.isWarnEnabled()) {
            log.warn("Null role name found while retrieving role names for user " +
              "[" + username + "]");
          }
        }
      }
    } finally {
      JdbcUtils.closeResultSet(rs);
      JdbcUtils.closeStatement(ps);
    }
    return roleNames;
  }

  public Set<String> getPermissions(Connection conn, String username,
                                       Collection<String> roleNames) throws SQLException {
    PreparedStatement ps = null;
    Set<String> permissions = new LinkedHashSet<String>();
    try {
      ps = conn.prepareStatement(permissionsQuery);
      for (String roleName : roleNames) {

        ps.setString(1, roleName);

        ResultSet rs = null;

        try {
          // Execute query
          rs = ps.executeQuery();

          // Loop over results and add each returned role to a set
          while (rs.next()) {

            String permissionString = rs.getString(1);

            // Add the permission to the set of permissions
            permissions.add(permissionString);
          }
        } finally {
          JdbcUtils.closeResultSet(rs);
        }

      }
    } finally {
      JdbcUtils.closeStatement(ps);
    }

    return permissions;
  }

  public String getSaltForUser(String username) {
    return username;
  }

}
