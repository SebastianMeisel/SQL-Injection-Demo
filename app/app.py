from flask import Flask, render_template, request, redirect, url_for, flash
import sqlite3
import os

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
            is_admin INTEGER DEFAULT 0
        )
        ''')
        
        # Insert sample data
        sample_users = [
            (1, 'admin', 'admin123', 'admin@example.com', 1),
            (2, 'alice', 'alice123', 'alice@example.com', 0),
            (3, 'bob', 'bob123', 'bob@example.com', 0),
            (4, 'charlie', 'charlie123', 'charlie@example.com', 0)
        ]
        
        cursor.executemany('''
        INSERT INTO users (id, username, password, email, is_admin)
        VALUES (?, ?, ?, ?, ?)
        ''', sample_users)
        
        # Create products table for another example
        cursor.execute('''
        CREATE TABLE products (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            description TEXT,
            price REAL NOT NULL
        )
        ''')
        
        # Insert sample products
        sample_products = [
            (1, 'Laptop', 'High-performance laptop', 999.99),
            (2, 'Smartphone', 'Latest smartphone model', 699.99),
            (3, 'Tablet', '10-inch tablet', 349.99),
            (4, 'Headphones', 'Noise-cancelling headphones', 149.99)
        ]
        
        cursor.executemany('''
        INSERT INTO products (id, name, description, price)
        VALUES (?, ?, ?, ?)
        ''', sample_products)
        
        conn.commit()
        conn.close()


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
                flash(f'Login successful! Welcome, {user[1]}!', 'success')
                if user[4] == 1:  # is_admin
                    flash('You are logged in as an admin!', 'info')
            else:
                flash('Invalid username or password!', 'danger')
                
        except sqlite3.Error as e:
            flash(f'Error: {str(e)}', 'danger')
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
                flash(f'Login successful! Welcome, {user[1]}!', 'success')
                if user[4] == 1:  # is_admin
                    flash('You are logged in as an admin!', 'info')
            else:
                flash('Invalid username or password!', 'danger')
                
        except sqlite3.Error as e:
            flash(f'Error: {str(e)}', 'danger')
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
        flash(f'Error: {str(e)}', 'danger')
        products = []
    finally:
        conn.close()
        
    return render_template('products.html', products=products, search=search, sort=sort)

@app.route('/users')
def dump_users_vulnerable():
    id = request.args.get('id', '')
    
    if not id:
        return "Please provide a user ID."
    
    # Vulnerable to SQL injection
    query = f"SELECT username, email FROM users WHERE id = {id}"
    
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    try:
        cursor.execute(query)
        user = cursor.fetchone()
        if user:
            return render_template('user.html', user=user)
        else:
            return "User not found."
    except sqlite3.Error as e:
        return f"Error: {str(e)}"
    finally:
        conn.close()


@app.route('/how-it-works')
def how_it_works():
    return render_template('how_it_works.html')


if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', debug=True)
