from flask import Flask, session, jsonify

app = Flask(__name__)
app.secret_key = 'supersecretkey'  # For session management

# Hardcoded users with roles
users = {
    'admin_user': 'admin',
    'regular_user': 'user'
}

@app.route('/login/<username>')
def login(username):
    if username in users:
        session['user'] = username
        session['role'] = users[username]
        return f"Logged in as {username} with role {users[username]}"
    else:
        return "User not found", 404

@app.route('/admin_action')
def admin_action():
    if session.get('role') == 'admin':
        return "Admin action performed: Access granted to admin-only resource."
    else:
        return "Access denied: Admin role required.", 403

@app.route('/user_action')
def user_action():
    if session.get('role') == 'user':
        return "User action performed: Access granted to user-only resource."
    else:
        return "Access denied: User role required.", 403

@app.route('/')
def home():
    user = session.get('user')
    role = session.get('role')
    if user:
        return f"Welcome {user}, your role is {role}"
    else:
        return "Please login first. Use /login/'username' where username is admin_user or regular_user"

if __name__ == '__main__':
    app.run(debug=True)

