

---

## Broken Access Control

### 1. Node.js Profile Fetching (Authorization Check)
We check if the `userId` requested matches the ID of the authenticated user.
```javascript
app.get('/profile/:userId', isAuthenticated, (req, res) => {
    // Ensure the logged-in user is only accessing their own data
    if (req.user.id !== req.params.userId) {
        return res.status(403).send("Unauthorized access");
    }

    User.findById(req.params.userId, (err, user) => {
        if (err) return res.status(500).send(err);
        res.json(user);
    });
});
```

### 2. Flask Account Query (Ownership Validation)
Using a library like Flask-Login to ensure the `current_user` owns the record.
```python
@app.route('/account/<user_id>')
@login_required
def get_account(user_id):
    # Verify the requester is the owner
    if current_user.id != int(user_id):
        return abort(403)
        
    user = db.query(User).filter_by(id=user_id).first()
    return jsonify(user.to_dict())
```

---

## Cryptographic Failures

### 3. Java Password Hashing (BCrypt)
```java
import org.mindrot.jbcrypt.BCrypt;

public String hashPassword(String password) {
    // BCrypt automatically generates a salt and includes it in the string
    return BCrypt.hashpw(password, BCrypt.gensalt(12));
}
```

### 4. Python Password Hashing (Argon2/Bcrypt)
```python
import bcrypt

def hash_password(password):
    byte_password = password.encode('utf-8')
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(byte_password, salt)
```

---

## Injection

### 5. Java SQL Injection (Prepared Statements)
```java
String username = request.getParameter("username");
String query = "SELECT * FROM users WHERE username = ?"; // Use a placeholder
PreparedStatement pstmt = connection.prepareStatement(query);
pstmt.setString(1, username); // The driver escapes this safely
ResultSet rs = pstmt.executeQuery();
```

### 6. Node.js NoSQL Injection (Type Casting)
```javascript
app.get('/user', (req, res) => {
    // Force the input to be a string
    const searchName = String(req.query.username);
    
    db.collection('users').findOne({ username: searchName }, (err, user) => {
        if (err) return res.status(500).send(err);
        res.json(user);
    });
});
```

---

## Insecure Design

### 7. Flask Password Reset (Token Verification)
```python
@app.route('/reset-password/<token>', methods=['POST'])
def reset_password(token):
    # Verify the token exists and hasn't expired
    email = verify_reset_token(token) 
    if not email:
        return "Invalid or expired token", 400
        
    new_password = request.form['new_password']
    user = User.query.filter_by(email=email).first()
    user.password = hash_function(new_password) # Never store plaintext!
    db.session.commit()
    return 'Password updated successfully'
```

---

## Software and Data Integrity Failures

### 8. External Script (Subresource Integrity)
```html
<script 
  src="https://cdn.example.com/lib.js" 
  integrity="sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxy9rx7HNQlGYl1kPzQho1wx4JwY8wC" 
  crossorigin="anonymous">
</script>
```

---

## Server-Side Request Forgery (SSRF)

### 9. Python URL Fetcher (Allow-listing)
```python
from urllib.parse import urlparse

ALLOWED_DOMAINS = ['api.trustedpartner.com', 'images.public.com']

def safe_fetch(user_url):
    parsed_url = urlparse(user_url)
    if parsed_url.netloc not in ALLOWED_DOMAINS:
        return "Access Denied", 403
        
    response = requests.get(user_url, timeout=5)
    return response.text
```

---

## Identification and Authentication Failures

### 10. Java Password Verification (Secure Comparison)
```java
// user.getPassword() now returns the BCrypt hash from the DB
if (BCrypt.checkpw(inputPassword, user.getPassword())) {
    // Login success
} else {
    // Login failure
}
```
