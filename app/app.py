from flask import Flask, render_template, request, redirect, url_for, flash, session, g
import sqlite3
import os
from functools import wraps
from multilang import get_text, get_locale, LANGUAGES

app = Flask(__name__)
app.secret_key = 'vulnerable_secret_key'
DB_PATH = 'database.db'


def init_db():
    # Create database and sample tables if they don't exist
    if not os.path.exists(DB_PATH):
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # Create users table
        cursor.execute('''
        CREATE TABLE users (
            id INTEGER PRIMARY KEY,
            username TEXT NOT NULL,
            password TEXT NOT NULL,
            email TEXT NOT NULL,
            is_admin INTEGER DEFAULT 0,
            last_login TEXT,
            login_attempts INTEGER DEFAULT 0
        )
        ''')
        
        # Insert sample data
        sample_users = [
            (1, 'admin', 'admin123', 'admin@example.com', 1, None, 0),
            (2, 'alice', 'alice123', 'alice@example.com', 0, None, 0),
            (3, 'bob', 'bob123', 'bob@example.com', 0, None, 0),
            (4, 'charlie', 'charlie123', 'charlie@example.com', 0, None, 0)
        ]
        
        cursor.executemany('''
        INSERT INTO users (id, username, password, email, is_admin, last_login, login_attempts)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', sample_users)
        
        # Create products table for another example
        cursor.execute('''
        CREATE TABLE products (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            description TEXT,
            price REAL NOT NULL,
            stock INTEGER DEFAULT 0,
            category TEXT
        )
        ''')
        
        # Insert sample products
        sample_products = [
            (1, 'Laptop', 'High-performance laptop', 999.99, 10, 'Electronics'),
            (2, 'Smartphone', 'Latest smartphone model', 699.99, 15, 'Electronics'),
            (3, 'Tablet', '10-inch tablet', 349.99, 8, 'Electronics'),
            (4, 'Headphones', 'Noise-cancelling headphones', 149.99, 20, 'Accessories')
        ]
        
        cursor.executemany('''
        INSERT INTO products (id, name, description, price, stock, category)
        VALUES (?, ?, ?, ?, ?, ?)
        ''', sample_products)
        
        # Create a new audit_log table for demonstration
        cursor.execute('''
        CREATE TABLE audit_log (
            id INTEGER PRIMARY KEY,
            action TEXT NOT NULL,
            username TEXT,
            timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
            ip_address TEXT,
            details TEXT
        )
        ''')
        
        conn.commit()
        conn.close()

# Before each request, make get_text available to templates
@app.before_request
def before_request():
    g.get_text = get_text
    g.get_locale = get_locale
    g.languages = LANGUAGES

@app.route('/language/<language>')
def set_language(language):
    """Set the language for the session"""
    if language in LANGUAGES:
        session['language'] = language
    return redirect(request.referrer or url_for('index'))

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/login', methods=['GET', 'POST'])
def login_vulnerable():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # Vulnerable SQL query (NO PARAMETERIZATION)
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
        
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        try:
            cursor.execute(query)
            user = cursor.fetchone()
            
            if user:
                # Log successful login
                log_query = f"INSERT INTO audit_log (action, username, ip_address, details) VALUES ('login', '{user[1]}', '{request.remote_addr}', 'Successful login via vulnerable form')"
                cursor.execute(log_query)
                
                # Update last login timestamp
                update_query = f"UPDATE users SET last_login = CURRENT_TIMESTAMP, login_attempts = 0 WHERE id = {user[0]}"
                cursor.execute(update_query)
                
                conn.commit()
                flash(get_text('login_successful', user[1]), 'success')
                if user[4] == 1:  # is_admin
                    flash(get_text('admin_login'), 'info')
            else:
                flash(get_text('invalid_credentials'), 'danger')
                
        except sqlite3.Error as e:
            flash(get_text('error', str(e)), 'danger')
        finally:
            conn.close()
            
    return render_template('login.html')

@app.route('/login_safe', methods=['GET', 'POST'])
def login_safe():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # Safe SQL query (WITH PARAMETERIZATION)
        query = "SELECT * FROM users WHERE username = ? AND password = ?"
        
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        try:
            cursor.execute(query, (username, password))
            user = cursor.fetchone()
            
            if user:
                # Log successful login using parameterized query
                log_query = "INSERT INTO audit_log (action, username, ip_address, details) VALUES (?, ?, ?, ?)"
                cursor.execute(log_query, ('login', user[1], request.remote_addr, 'Successful login via safe form'))
                
                # Update last login timestamp using parameterized query
                update_query = "UPDATE users SET last_login = CURRENT_TIMESTAMP, login_attempts = 0 WHERE id = ?"
                cursor.execute(update_query, (user[0],))
                
                conn.commit()
                flash(get_text('login_successful', user[1]), 'success')
                if user[4] == 1:  # is_admin
                    flash(get_text('admin_login'), 'info')
            else:
                # Record failed login attempt in a safe way
                if username:
                    attempt_query = "UPDATE users SET login_attempts = login_attempts + 1 WHERE username = ?"
                    cursor.execute(attempt_query, (username,))
                    conn.commit()
                flash(get_text('invalid_credentials'), 'danger')
                
        except sqlite3.Error as e:
            flash(get_text('error', str(e)), 'danger')
        finally:
            conn.close()
            
    return render_template('login_safe.html')

@app.route('/products')
def products_vulnerable():
    search = request.args.get('search', '')
    sort = request.args.get('sort', 'id')
    
    # Vulnerable to SQL injection in the ORDER BY clause
    query = f"SELECT * FROM products"
    if search:
        query += f" WHERE name LIKE '%{search}%' OR description LIKE '%{search}%'"
    query += f" ORDER BY {sort}"
    
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    try:
        cursor.execute(query)
        # Convert sqlite3.Row objects to dictionaries
        products = [dict(row) for row in cursor.fetchall()]
    except sqlite3.Error as e:
        flash(get_text('error', str(e)), 'danger')
        products = []
    finally:
        conn.close()
        
    return render_template('products.html', products=products, search=search, sort=sort)

@app.route('/users')
def dump_users_vulnerable():
    id = request.args.get('id', '')
    
    if not id:
        return get_text('provide_user_id')
    
    # Vulnerable to SQL injection
    query = f"SELECT username, email, is_admin, last_login FROM users WHERE id = {id}"
    
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    try:
        cursor.execute(query)
        user = cursor.fetchone()
        if user:
            return render_template('user.html', user=dict(user))
        else:
            return get_text('user_not_found')
    except sqlite3.Error as e:
        return get_text('error', str(e))
    finally:
        conn.close()

@app.route('/how-it-works')
def how_it_works():
    return render_template('how_it_works.html')

@app.route('/db-details')
def db_details():
    """Show database structure details for educational purposes"""
    return render_template('db_details.html')

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', debug=True)
