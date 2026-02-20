from flask import Flask, render_template, request, redirect, url_for, flash, session
import sqlite3
import os
from werkzeug.security import generate_password_hash, check_password_hash
from zxcvbn import zxcvbn
from datetime import timedelta
from dotenv import load_dotenv
load_dotenv()
app = Flask(__name__)
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=7)
app.secret_key = os.getenv('FLASK_SECRET_KEY', 'default-key-for-dev') 

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE = os.path.join(BASE_DIR, 'users.db')

def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row 
    return conn

with get_db_connection() as conn:
    conn.execute('''CREATE TABLE IF NOT EXISTS users 
                    (id INTEGER PRIMARY KEY AUTOINCREMENT, 
                     username TEXT NOT NULL UNIQUE, 
                     password_hash TEXT NOT NULL)''')

@app.route('/')
def index():
    if 'username' in session:
        return redirect(url_for('profile'))
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    username = ""
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')

        if len(username) >= 23 or len(password) >= 23:
            flash('Имя или пароль слишком длинные. Максимум 22 символа.', 'error')
            return render_template('register.html', username=username)

        results = zxcvbn(password, user_inputs=[username])
        if results['score'] < 3:
           
            reason = results['feedback']['warning']
            
            suggestion = results['feedback']['suggestions'][0] if results['feedback']['suggestions'] else ""
            
            
            error_msg = f"Слабый шифр. {reason} {suggestion}"
            flash(error_msg, 'error')
            return render_template('register.html', username=username)
        
        hashed_pw = generate_password_hash(password)
        
        try:
            with get_db_connection() as conn:
                conn.execute('INSERT INTO users (username, password_hash) VALUES (?, ?)', 
                             (username, hashed_pw))
                conn.commit()
            flash('Теперь ты в системе. Попробуй войти.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Это имя уже занято.', 'error')
            return redirect(url_for('register'))

    return render_template('register.html', username=username)

@app.route('/login', methods=['GET', 'POST'])
def login():
    username = ""
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        
        with get_db_connection() as conn:
            user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()

        if len(username) >= 23 or len(password) >= 23:
            flash('Имя или пароль слишком длинные. Максимум 22 символа.', 'error')
            return render_template('login.html', username=username)


        if user and check_password_hash(user['password_hash'], password):
            session.permanent = True
            session['user_id'] = user['id']
            session['username'] = user['username']

            return redirect(url_for('profile'))
        
        flash('Неверное имя или пароль.', 'error')
    return render_template('login.html', username=username)

@app.route('/profile')
def profile():
    if 'user_id' not in session:
        flash('Сначала войди в систему.', 'error')
        return redirect(url_for('login'))
    return render_template('profile.html', username=session['username'])

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)
