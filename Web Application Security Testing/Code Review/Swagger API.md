### **Public Exposure of Swagger Documentation**

- **Verify accessibility**:
    - Check common paths like `/swagger-ui.html`, `/v2/api-docs`, `/v3/api-docs`or `/openapi.json`.
    - Ensure Swagger documentation is not publicly accessible in production environments.
- **Authentication**:
    - Restrict access to authorized users only.
    - Implement authentication mechanisms (e.g., API tokens or role-based access) for Swagger documentation.

### **Endpoint Exposure**

- **Sensitive endpoints**:
	- Identify endpoints such as `/health`, `/metrics`, `/env`, `configprops`, `beeans` or `/info`.
    - Ensure they do not disclose system details (e.g., versions, dependencies, or environment variables).
    - For Spring Boot, configure sensitive endpoints in `application.yml`:
```bash
management:
  endpoint:
    health:
      enabled: true
  endpoints:
    web:
      exposure:
        include: []
```