Authorization review focuses on verifying that users only have permissions to execute functions or access resources they are explicitly allowed to. Proper access control ensures that unauthorized users cannot exploit backend functionalities.

---

### Key Points to Review

1. **Role-Based Access Control (RBAC)**: Verify that roles are properly defined and enforced for each user action.
2. **Least Privilege Principle**: Ensure users and services have the minimum permissions necessary.
3. **Functionality Access**: Review APIs or backend endpoints to ensure they are protected from unauthorized access.
4. **Spring Security Policies**: If using **Spring Security**, confirm that the authorization rules are correctly configured.

---

### Method-Level Authorization in Spring Security

You can enforce fine-grained control at the method level using annotations:

- **`@PreAuthorize`**: Check permissions or roles before executing a method.
- **`@Secured`**: Restrict method access to specific roles.
- **`@RolesAllowed`**: An alternative to `@Secured` (from JSR 250).

```java
@PreAuthorize("hasRole('ADMIN')")
public void adminOnlyFunction() {
    // This function can only be executed by users with ADMIN role
}

@PreAuthorize("hasAnyRole('ADMIN', 'USER')")
public void userAndAdminFunction() {
    // Accessible to ADMIN or USER roles
}
```

#### Example of a bad Authorization Configuration

In the following example, access to all sensitive endpoints is unintentionally left open:

```java
@Override
protected void configure(HttpSecurity http) throws Exception {
    http
        .authorizeRequests()
            .antMatchers("/admin/**").permitAll()  // Anyone can access admin endpoints
            .antMatchers("/user/**").permitAll()
            .anyRequest().authenticated();
}
```

- The `permitAll()` rule allows any user, authenticated or not, to access critical administrative functions.
- Attackers can exploit this misconfiguration to perform unauthorized operations.


---

### JWT Validation
JSON Web Tokens (JWT) are commonly used for securing backend APIs by providing a compact and self-contained way to transmit user identity and claims. Proper validation of JWTs is critical to ensure that only authorized users can access protected resources.

#### Key Points for JWT Validation:

1. **Token Structure**:
    
    - Verify the JWT has the correct structure: `header.payload.signature`.
    - Ensure the signature is valid and matches the server's signing key.
2. **Authentication Filter**:
    
    - Check if the backend has a filter or middleware (e.g., `OncePerRequestFilter` in Spring Security) that:
        - Extracts the `Authorization` header.
        - Validates the JWT's signature, expiration, and claims.
        - Sets the authenticated user in the `SecurityContext`.
    
**Example of a JWT Authorization Filter**:

```java
@Component
public class JwtAuthorizationFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        String header = request.getHeader("Authorization");

        if (header == null || !header.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        String token = header.replace("Bearer ", "");
        try {
            Claims claims = Jwts.parser()
                    .setSigningKey("secretKey") // Replace with your secure signing key
                    .parseClaimsJws(token)
                    .getBody();

            String username = claims.getSubject();
            if (username != null) {
                UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                        username, null, new ArrayList<>());
                SecurityContextHolder.getContext().setAuthentication(authentication);
            }
        } catch (Exception e) {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            return;
        }

        filterChain.doFilter(request, response);
    }
}
```

3. **Validation Criteria**:
    
    - Ensure the token:
        - Is correctly signed with the server's secret key or public/private key pair (for RS256).
        - Has not expired (`exp` claim).
        - Contains valid claims (e.g., roles, permissions).
    - Reject tokens with invalid structures, signatures, or claims.
4. **Token Expiry and Revocation**:
    
    - Check the `exp` (expiration) claim to ensure the token is still valid.
    - Implement a mechanism for token revocation if needed (e.g., maintaining a blacklist or a token invalidation list).
5. **Secure Token Storage**:
    
    - Ensure JWTs are securely stored on the client side (e.g., in `HttpOnly` cookies or secure local storage).
    - Prevent misuse of tokens by ensuring they are transmitted over HTTPS.
6. **Testing JWT Handling**:
    
    - Test API endpoints by:
        - Sending requests with valid tokens to verify proper access.
        - Sending expired, malformed, or tampered tokens to confirm they are rejected.
        - Omitting the `Authorization` header to check for unauthorized responses.