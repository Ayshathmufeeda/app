from flask import Flask, render_template_string, request, redirect, session, url_for, flash
import sqlite3
import bcrypt
import re

app = Flask(__name__)
app.secret_key = 'change-this-to-a-random-secret-key' # Important for sessions

# Database setup
def init_db():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users 
                 (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password_hash TEXT)''')
    conn.commit()
    conn.close()

init_db()

# Basic input validation
def is_valid_username(username):
    return bool(re.match("^[a-zA-Z0-9_]{3,20}$", username))

def is_valid_password(password):
    return len(password) >= 8

# HTML Templates - keeping it in one file for simplicity
LOGIN_PAGE = '''
<h2>Login</h2>
{% with messages = get_flashed_messages() %}
  {% if messages %}{% for msg in messages %}<p style="color:red">{{ msg }}</p>{% endfor %}{% endif %}
{% endwith %}
<form method="POST">
  Username: <input name="username" required><br><br>
  Password: <input name="password" type="password" required><br><br>
  <input type="submit" value="Login">
</form>
<a href="{{ url_for('register') }}">Register</a>
'''

REGISTER_PAGE = '''
<h2>Register</h2>
{% with messages = get_flashed_messages() %}
  {% if messages %}{% for msg in messages %}<p style="color:red">{{ msg }}</p>{% endfor %}{% endif %}
{% endwith %}
<form method="POST">
  Username: <input name="username" required><br><br>
  Password: <input name="password" type="password" required><br><br>
  <input type="submit" value="Register">
</form>
<a href="{{ url_for('login') }}">Login</a>
'''

HOME_PAGE = '''
<h2>Welcome, {{ username }}!</h2>
<p>You are logged in successfully.</p>
<a href="{{ url_for('logout') }}">Logout</a>
'''

@app.route('/')
def home():
    if 'username' in session:
        return render_template_string(HOME_PAGE, username=session['username'])
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']

        # 1. Input validation
        if not is_valid_username(username):
            flash('Username must be 3-20 characters, letters/numbers/underscore only')
            return redirect(url_for('register'))
        if not is_valid_password(password):
            flash('Password must be at least 8 characters')
            return redirect(url_for('register'))

        # 2. Hash password with bcrypt
        password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        # 3. SQL injection protection: parameterized query
        try:
            conn = sqlite3.connect('users.db')
            c = conn.cursor()
            c.execute("INSERT INTO users (username, password_hash) VALUES (?,?)", (username, password_hash))
            conn.commit()
            conn.close()
            flash('Registration successful! Please login.')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username already exists')
            return redirect(url_for('register'))
    
    return render_template_string(REGISTER_PAGE)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # SQL injection protection: parameterized query
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        c.execute("SELECT password_hash FROM users WHERE username =?", (username,))
        result = c.fetchone()
        conn.close()

        if result and bcrypt.checkpw(password.encode('utf-8'), result[0]):
            # 4. Session management
            session['username'] = username
            return redirect(url_for('home'))
        else:
            flash('Invalid username or password')
            return redirect(url_for('login'))

    return render_template_string(LOGIN_PAGE)

@app.route('/logout')
def logout():
    session.pop('username', None) # Clear session
    flash('Logged out successfully')
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)