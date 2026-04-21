# OWASP Vulnerabilities Explanation

1. **Vulnerability: Insecure Direct Object Reference (IDOR).**

   The code fetches a user based solely on the userId provided in the URL. It never checks if the currently logged-in user actually has permission to view that specific profile. An attacker could simply change the ID in the browser to view any user's private data.

2. **Vulnerability: IDOR / Horizontal Privilege Escalation.**

   Similar to the first example, this Python snippet lacks an authorization layer. It assumes that if a user knows an account ID, they are authorized to see it. It should verify that current_user.id == user_id.

## Cryptographic Failures

3. **Vulnerability: Weak/Broken Hashing Algorithm and No Salting.**

   MD5 is cryptographically "broken"—it is susceptible to collision attacks and can be cracked almost instantly. Furthermore, because there is no Salt (a random string added to the password), the hash is vulnerable to pre-computed "Rainbow Table" attacks.

4. **Vulnerability: Insufficient Password Hashing.**

   SHA-1 is also considered weak and insecure for passwords. Like the Java example, it lacks a salt and is too fast; modern hardware can guess billions of SHA-1 hashes per second, making brute-force attacks trivial.

## Injection

5. **Vulnerability: SQL Injection**

   The code uses string concatenation to build a database query. An attacker could enter a username like ' OR '1'='1, changing the logic of the query to bypass authentication or dump the entire database.

6. **Vulnerability: NoSQL Injection.**

   By passing req.query.username directly into a MongoDB query, an attacker can pass an object instead of a string. For example, if they send { "$gt": "" }, the query becomes "find a user where the username is greater than nothing," which returns the first user in the database (usually the admin).

## Insecure Design

7. **Vulnerability: Insecure Logic / Lack of Verification.**

   This "reset" function doesn't actually verify anything. There's no secret token sent to an email, no "old password" check, and no MFA. Anyone who knows a user's email can change that user's password to whatever they want.

## Software and Data Integrity Failures

8. **Vulnerability: Missing Subresource Integrity (SRI).**

   You are trusting a third-party CDN blindly. If cdn.example.com gets hacked, the attacker can swap lib.js with malicious code that steals your users' cookies. You should use an integrity attribute (a cryptographic hash) to ensure the file hasn't been tampered with.

## Server-Side Request Forgery (SSRF)

9. **Vulnerability: SSRF.**

   The application takes a URL from the user and makes a request to it from the server. An attacker could input http://localhost:8080/admin or cloud metadata URLs (like http://169.254.169.254) to access internal services that aren't supposed to be public.

## Identification and Authentication Failures

10. **Vulnerability: Plaintext Password Storage/Comparison.**

    The use of .equals() suggests that both the input and the stored password are plain strings. If your database is ever leaked, every single user password is exposed instantly. Passwords should always be compared using a secure, constant-time function against a salted hash (like Argon2 or BCrypt).