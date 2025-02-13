
## Vulnerable query
- The `username` and `password` variables are likely derived from user input, such as form fields or HTTP requests.
- Directly embedding these inputs into the SQL string without sanitization or parameterization allows attackers to manipulate the query structure.
```java
String query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'";
```

## Safe query using Prepared Statement
- In a `PreparedStatement`, the SQL query is precompiled by the database server with placeholders (`?`) for parameters.
- User inputs are then bound to these placeholders using setter methods like `.setString()`. This separates SQL logic from user data, ensuring no part of the input is executed as SQL commands.

```java
String query = "SELECT * FROM users WHERE username = ? AND password = ?";
PreparedStatement pstmt = connection.prepareStatement(query);
pstmt.setString(1, username); // Bind 'username' to the first placeholder
pstmt.setString(2, password); // Bind 'password' to the second placeholder
ResultSet rs = pstmt.executeQuery();
```

## Safe query using Mybatis
- **`#{}` **: These placeholders indicate MyBatis will use parameterized queries. The input is escaped automatically.
- The query is precompiled, ensuring user input cannot alter the structure of the SQL statement.

With Mybatis, you can define the query in an XML configuration file:

**Mapper XML**
```xml
<mapper namespace="com.example.mapper.UserMapper">
    <select id="findByUsernameAndPassword" parameterType="map" resultType="User">
        SELECT * FROM users
        WHERE username = #{username} AND password = #{password}
    </select>
</mapper>
```
**Java Method**
```java
Map<String, String> params = new HashMap<>();
params.put("username", "admin");
params.put("password", "securePassword");
User user = userMapper.findByUsernameAndPassword(params);
```

#### Common Error in MyBatis
**Using `${}` Instead of `#{}` for Parameters**
- **Issue**: MyBatis uses `${}` to directly inject values into SQL, which makes it vulnerable to SQL Injection if the values are user-controlled.
```xml
<select id="findByUsername" resultType="User">
    SELECT * FROM users WHERE username = '${username}'
</select>
```