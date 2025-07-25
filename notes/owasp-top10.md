# OWASP Top 10 (2021)

A summary of the most critical security risks to web applications.

---

## 1. Broken Access Control
Improper enforcement of user permissions. Attackers can gain unauthorized access to resources or functions.

**Examples:** Bypassing access control checks, modifying URLs or tokens to access unauthorized data.

---

## 2. Cryptographic Failures
Previously known as "Sensitive Data Exposure". Focuses on failures in data protection mechanisms.

**Examples:** Weak or no encryption, outdated TLS, hardcoded keys, exposed passwords.

---

## 3. Injection
Untrusted data sent to an interpreter can result in code execution.

**Examples:** SQL injection, OS command injection, LDAP injection.

---

## 4. Insecure Design
New category emphasizing the need for security-by-design practices.

**Examples:** Missing security controls, lack of threat modeling, insecure default behavior.

---

## 5. Security Misconfiguration
Improper configurations or default settings can be exploited.

**Examples:** Open S3 buckets, exposed admin interfaces, verbose error messages.

---

## 6. Vulnerable and Outdated Components
Using known-vulnerable libraries, frameworks, or other components.

**Examples:** Running outdated versions of libraries or dependencies with known CVEs.

---

## 7. Identification and Authentication Failures
Issues with identity, session management, and authentication.

**Examples:** Brute force, session fixation, improper password storage.

---

## 8. Software and Data Integrity Failures
New category focusing on software supply chain and integrity issues.

**Examples:** Unsigned or tampered code, CI/CD pipeline vulnerabilities.

---

## 9. Security Logging and Monitoring Failures
Inadequate logging and monitoring can delay or prevent breach detection.

**Examples:** Lack of alerting, poor log hygiene, missing logs on critical events.

---

## 10. Server-Side Request Forgery (SSRF)
Exploits where attackers can coerce servers into making requests to unintended locations.

**Examples:** Fetching internal resources, metadata service abuse on cloud platforms.
