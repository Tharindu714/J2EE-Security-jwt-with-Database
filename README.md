# 🛡️ J2EE Security with JWT & Database

> A Jakarta EE application demonstrating stateless authentication using JSON Web Tokens (JWT) backed by a database IdentityStore and JPA persistence.

---

## 📑 Table of Contents

1. [🚧 Prerequisites](#-prerequisites)
2. [🛠️ Database & JDBC Setup](#️-database--jdbc-setup)
3. [⚙️ `persistence.xml` & JPA Config](#-persistencexml--jpa-config)
4. [🔍 Theory: Persistence, Security, JWT](#-theory-persistence-security-jwt)
5. [📂 Project Structure](#-project-structure)
6. [🔐 Security Components](#-security-components)

   * [Database IdentityStore](#database-identitystore)
   * [JWTUtility](#jwtutility)
   * [JWTAuthenticationFilter](#jwtauthenticationfilter)
7. [🚀 Usage & Endpoints](#-usage--endpoints)
8. [🛠️ Configuration Snippets](#️-configuration-snippets)
9. [📷 Screenshots](#-screenshots)
10. [🤝 Contribution](#-contribution)
11. [📜 License](#-license)

---

## 🚧 Prerequisites

* **Java 11+**, **Maven**
* **Jakarta EE–compliant server** (WildFly, Payara)
* **MySQL** or other RDBMS

---

## 🛠️ Database & JDBC Setup

1. **Create DB & Tables**:

   ```sql
   CREATE DATABASE j2ee_security_db;
   USE j2ee_security_db;
   ```
2. **Seed data** with bcrypt-hashed passwords.
3. **JDBC DataSource**: configure in your server, e.g. WildFly `standalone.xml`:

   ```xml
   <datasource jndi-name="java:/jdbc/JwtDS" pool-name="JwtPool">
     <connection-url>jdbc:mysql://localhost:3306/jwt_security</connection-url>
     <driver>mysql</driver>
     <security><user-name>dbuser</user-name><password>dbpass</password></security>
   </datasource>
   ```

---

## ⚙️ `persistence.xml` & JPA Config

Place under `src/main/resources/META-INF/persistence.xml`:

```xml
<?xml version="1.0" encoding="UTF-8" ?>
<persistence xmlns="https://jakarta.ee/xml/ns/persistence" version="3.0">
    <persistence-unit name="j2eeSecuredAppDB" transaction-type="JTA">
        <provider>org.hibernate.jpa.HibernatePersistenceProvider</provider>
        <jta-data-source>j2ee_security_db</jta-data-source>
        <properties>
            <property name="hibernate.dialect" value="org.hibernate.dialect.MySQLDialect"/>
            <property name="hibernate.transaction.jta.platform" value="org.hibernate.engine.transaction.jta.platform.internal.SunOneJtaPlatform"/>
            <property name="hibernate.hbm2ddl.auto" value="update"/>
            <property name="hibernate.show_sql" value="true"/>
        </properties>
    </persistence-unit>
</persistence>
```

---

## 🔍 Theory: Persistence, Security, JWT

* **JDBC Pooling**: Reuses DB connections for efficiency.
* **JPA & JTA**: Container-managed transactions ensure ACID integrity.
* **IdentityStore**: Centralizes user/role lookups from the database.
* **JWT**: Stateless tokens carrying claims (e.g., `sub`, `roles`, `exp`), signed with HMAC-SHA256 to prevent tampering.

---

## 📂 Project Structure

```
src/main/java/com/tharindu/jwt/
├── config/
│   └── AppConfig.java         
├── controller/
│   └── AuthController.java          
├── DTO/
│   └── Credentials.java
├── Security/
│   ├── AuthMechanism.java   
│   └── AppIdentityStore.java
├── service/
│   └── UserService.java
├── servlet/
│   ├── Login.java   
│   └── Profile.java
├── Entity/
│   └── User.java
└── Util/
    └── JWUtil.java             

src/main/resources/
└── META-INF/persistence.xml

src/main/webapp/
├── login.jsp
├── index.jsp
├── home.jsp                     
└── WEB-INF/
    └── web.xml  # Security constraints and filter mapping
```

---

## 🔐 Security Components

### Database IdentityStore

```java
    @Override
    public CredentialValidationResult validate(Credential credential) {
        System.out.println("Validating credential: " + credential);
        if (credential instanceof UsernamePasswordCredential) {
            UsernamePasswordCredential UPC = (UsernamePasswordCredential) credential;
            if (loginService.validate(UPC.getCaller(), UPC.getPasswordAsString())) {
                Set<String> roles = loginService.getRoles(UPC.getCaller());

                return new CredentialValidationResult(UPC.getCaller(), roles);
            }
        }
//        return IdentityStore.super.validate(credential);
        return CredentialValidationResult.INVALID_RESULT;
    }
```

### JWTUtility

```java
    public static String generateToken(String username, Set<String> roles) {
      return Jwts.builder()
                .subject(username)
                .claim("roles", roles)
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + EXPIRATION_TIME))
                .signWith(SECRET_KEY,Jwts.SIG.HS256)
                .compact();
    }

```

### JWTAuthenticationFilter

```java
    @Override
    public AuthenticationStatus validateRequest(HttpServletRequest Request, HttpServletResponse Response, HttpMessageContext Context) throws AuthenticationException {

        String authHeader = Request.getHeader(HttpHeaders.AUTHORIZATION);
        if (authHeader != null && !authHeader.startsWith("Bearer ")) {
            try {
                String token = authHeader.substring(7); // Extract the token
                Claims claims = JWTUtil.parseToken(token).getPayload();
                String username = claims.getSubject();
                List roles = claims.get("roles", List.class);

                CredentialValidationResult CVR = new CredentialValidationResult(username, new HashSet<>(roles));
                return Context.notifyContainerAboutLogin(CVR);
            }catch (JwtException JE){
                return Context.responseUnauthorized();
            }
        }
}
```

---

## 🚀 Usage & Endpoints

1. **Login**: POST `/login` with JSON body:

   ```json
   {"username":"admin","password":"Secret123"}
   ```

   * **Response**: `200 OK` with JSON `{ "token": "<JWT>" }`.
2. **Access Protected**: GET `/api/protected` with header:

   ```http
   Authorization: Bearer <JWT_TOKEN>
   ```

   * **Success**: `200 OK` with resource payload.
   * **Failure**: `401 Unauthorized` if token is invalid or expired.

---

## 🛠️ Configuration Snippets

* **web.xml**: Map `JWTAuthenticationFilter` to `/api/*`, leave `/login` open.
* **beans.xml**: Register filter if using CDI discovery.

---

## 📷 Screenshots

```markdown
Design not created -- Focusing oin Backend
```

---

## 🤝 Contribution

Fork the repo, create a feature branch, and open a PR. Ensure JWT and IdentityStore tests are included.

---

## 📜 License

MIT © 2025 Tharindu714

---

> Stateless, scalable security with JWT and JPA in Jakarta EE! 🚀
