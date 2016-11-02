/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.zeppelin.rest;

import org.apache.commons.lang3.StringUtils;
import org.apache.shiro.authc.*;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.util.JdbcUtils;
import org.apache.zeppelin.annotation.ZeppelinApi;
import org.apache.zeppelin.server.JsonResponse;
import org.apache.zeppelin.ticket.TicketContainer;
import org.apache.zeppelin.utils.SecurityUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.ws.rs.FormParam;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Response;
import java.io.IOException;
import java.io.InputStream;
import java.sql.*;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Properties;

/**
 * Created for org.apache.zeppelin.rest.message on 17/03/16.
 */

@Path("/login")
@Produces("application/json")
public class LoginRestApi {
  private static final Logger LOG = LoggerFactory.getLogger(LoginRestApi.class);


  private static String DB_URL = "";
  private static String DB_USERNAME = "";
  private static String DB_PASSWORD = "";
  private static String ZE_PASSWORD = "";

  static {
    Properties prop = new Properties();
    InputStream in = Object.class.getResourceAsStream("/application.properties");
    try {
      prop.load(in);
      DB_URL = prop.getProperty("url").trim();
      DB_USERNAME = prop.getProperty("username").trim();
      DB_PASSWORD = prop.getProperty("password").trim();
      ZE_PASSWORD = prop.getProperty("zeppelin.login.password").trim();
    } catch (IOException e) {
      LOG.error("application.properties file not loaded success...");
    }
  }

  /**
   * Required by Swagger.
   */
  public LoginRestApi() {
    super();
  }


  /**
   * Post Login
   * Returns userName & password
   * for anonymous access, username is always anonymous.
   * After getting this ticket, access through websockets become safe
   *
   * @return 200 response
   */
  @POST
  @ZeppelinApi
  public Response postLogin(@FormParam("userName") String userName,
                            @FormParam("password") String password) {
    JsonResponse response = null;
    // ticket set to anonymous for anonymous user. Simplify testing.
    Subject currentUser = org.apache.shiro.SecurityUtils.getSubject();


    LOG.info("currentUser: " + currentUser.getPrincipal());

    if (StringUtils.isNotEmpty(password) && ZE_PASSWORD.equalsIgnoreCase(password.trim())) {

      LOG.info("login from datacenter platform..., username is: " + userName);
      //判断是否需要在Shiro权限表中新建用户
      isCreateShiroUser(userName);
    }

    if (currentUser.isAuthenticated()) {
      currentUser.logout();
    }
    if (!currentUser.isAuthenticated()) {
      try {
        UsernamePasswordToken token = new UsernamePasswordToken(userName, password);
        //      token.setRememberMe(true);
        currentUser.login(token);
        HashSet<String> roles = SecurityUtils.getRoles();
        String principal = SecurityUtils.getPrincipal();
        String ticket;
        if ("anonymous".equals(principal))
          ticket = "anonymous";
        else
          ticket = TicketContainer.instance.getTicket(principal);

        Map<String, String> data = new HashMap<>();
        data.put("principal", principal);
        data.put("roles", roles.toString());
        data.put("ticket", ticket);

        response = new JsonResponse(Response.Status.OK, "", data);
        //if no exception, that's it, we're done!
      } catch (UnknownAccountException uae) {
        //username wasn't in the system, show them an error message?
        LOG.error("Exception in login: ", uae);
      } catch (IncorrectCredentialsException ice) {
        //password didn't match, try again?
        LOG.error("Exception in login: ", ice);
      } catch (LockedAccountException lae) {
        //account for that username is locked - can't login.  Show them a message?
        LOG.error("Exception in login: ", lae);
      } catch (AuthenticationException ae) {
        //unexpected condition - error?
        LOG.error("Exception in login: ", ae);
      }
    }

    if (response == null) {
      response = new JsonResponse(Response.Status.FORBIDDEN, "", "");
    }

    LOG.warn(response.toString());
    return response.build();
  }

  @POST
  @Path("logout")
  @ZeppelinApi
  public Response logout() {
    JsonResponse response;
    Subject currentUser = org.apache.shiro.SecurityUtils.getSubject();
    currentUser.logout();
    response = new JsonResponse(Response.Status.UNAUTHORIZED, "", "");
    LOG.warn(response.toString());
    return response.build();
  }


  /**
   * 判断是否需要在Shiro权限表中新建用户；
   * 根据用户名去数据库查询用户名是否存在；
   *    存在：不做任何操作
   *    不存在：根据传递过来的userName在Zeppelin的用户表中创建一个用户
   * @param userName  登录的用户名
   * @author luogankun
   */
  private void isCreateShiroUser(String userName) {

    Connection conn = null;
    PreparedStatement ps = null;
    ResultSet rs = null;

    try {
      conn = DriverManager.getConnection(DB_URL, DB_USERNAME, DB_PASSWORD);
      ps = conn.prepareStatement("SELECT COUNT(1) FROM sec_user WHERE user_name=?");
      ps.setString(1, userName);
      rs = ps.executeQuery();
      if (rs.next()) {
        if (rs.getInt(1) == 0) {  //不存在
          LOG.info("the user " + userName + " not exist, create new zeppelin user...");
          ps = conn.prepareStatement("INSERT INTO sec_user (user_name, password) values(?, ?)");
          ps.setString(1, userName);
          ps.setString(2, ZE_PASSWORD);
          ps.execute();
        }
      }
    } catch (SQLException e) {
      e.printStackTrace();
    } finally {
      JdbcUtils.closeResultSet(rs);
      JdbcUtils.closeStatement(ps);
      JdbcUtils.closeConnection(conn);
    }
  }


}
