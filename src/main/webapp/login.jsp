<%--
  Created by IntelliJ IDEA.
  User: tharidu
  Date: 6/26/2025
  Time: 10:54 AM
  To change this template use File | Settings | File Templates.
--%>
<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<html>
<head>
    <title>Login Page</title>
</head>
<body>
<h1>Login</h1>
<form method="POST" action="${pageContext.request.contextPath}/login">
  <table>
    <tr>
        <td>Username:</td>
        <td><input type="text" name="username" required></td>
    </tr>
    <tr>
        <td>Password:</td>
        <td><input type="password" name="password" required></td>
    </tr>
    <tr>
        <td colspan="2"><input type="submit" value="Login"></td>
    </tr>
  </table>
</form>
</body>
</html>
