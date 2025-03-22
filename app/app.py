from flask import Flask, render_template, request, redirect, url_for, flash, session, g
import sqlite3
import os
from functools import wraps

app = Flask(__name__)
app.secret_key = 'vulnerable_secret_key'
DB_PATH = 'database.db'

# Available languages
LANGUAGES = {
    'en': 'English',
    'de': 'Deutsch'
}

# Translations dictionary
TRANSLATIONS = {
    'en': {
        'app_name': 'SQL Injection Demo',
        'home': 'Home',
        'vulnerable_login': 'Vulnerable Login',
        'safe_login': 'Safe Login',
        'products_search': 'Products Search',
        'how_it_works': 'How It Works',
        'username': 'Username',
        'password': 'Password',
        'login': 'Login',
        'login_successful': 'Login successful! Welcome, {}!',
        'admin_login': 'You are logged in as an admin!',
        'invalid_credentials': 'Invalid username or password!',
        'error': 'Error: {}',
        'search': 'Search',
        'sort_by': 'Sort by',
        'id': 'ID',
        'name': 'Name',
        'price': 'Price',
        'description': 'Description',
        'user_not_found': 'User not found.',
        'provide_user_id': 'Please provide a user ID.',
        'understanding_sql_injection': 'Understanding SQL Injection',
        'sql_injection_description': 'SQL Injection is a code injection technique that exploits security vulnerabilities in an application\'s software by inserting malicious SQL statements into entry fields for execution.',
        'common_techniques': 'Common SQL Injection Techniques',
        'auth_bypass': 'Authentication Bypass',
        'example': 'Example:',
        'example_explanation': 'When this is injected into a login form:',
        'or_true_explanation': 'The OR \'1\'=\'1\' always evaluates to true, causing the query to return results regardless of username or password.',
        'union_attack': 'UNION-Based Attacks',
        'union_explanation': 'UNION allows combining results from multiple SELECT statements:',
        'union_example': '\' UNION SELECT username, password FROM users--',
        'union_result': 'This can retrieve data from other tables in the database.',
        'blind_injection': 'Blind SQL Injection',
        'blind_explanation': 'Used when error messages are suppressed:',
        'blind_example': '\' OR (SELECT 1 FROM users WHERE username=\'admin\' AND SUBSTR(password,1,1)=\'a\')=1--',
        'blind_result': 'This allows extracting data character by character based on true/false conditions.',
        'language': 'Language',
        'detailed_explanation': 'Detailed SQL Injection Explanation',
        'prevention': 'Prevention Techniques',
        'param_queries': 'Parameterized Queries',
        'param_explanation': 'Use prepared statements with parameterized queries to separate SQL code from data.',
        'input_validation': 'Input Validation',
        'validation_explanation': 'Implement strict input validation on both client and server side.',
        'least_privilege': 'Principle of Least Privilege',
        'privilege_explanation': 'Database accounts used by applications should have minimal privileges.',
        'escape_chars': 'Escaping Special Characters',
        'escape_explanation': 'Properly escape special characters in user inputs before using them in SQL queries.',
        'orm': 'Use ORM Frameworks',
        'orm_explanation': 'Object-Relational Mapping frameworks often have built-in protection against SQL injection.',
        'waf': 'Web Application Firewall',
        'waf_explanation': 'Implement a WAF to filter out malicious SQL injection attempts.',
        'db_details': 'Database Details',
        'table_structure': 'Table Structure',
        'users_table': 'Users Table',
        'products_table': 'Products Table',
        'column': 'Column',
        'data_type': 'Data Type',
        'primary_key': 'Primary Key',
        'payload_examples': 'SQL Injection Payload Examples',
        'vulnerability_types': 'Types of SQL Injection Vulnerabilities',
        'error_based': 'Error-Based',
        'time_based': 'Time-Based',
        'out_of_band': 'Out-of-Band'
    },
    'de': {
        'app_name': 'SQL-Injection Demo',
        'home': 'Startseite',
        'vulnerable_login': 'Angreifbares Login',
        'safe_login': 'Sicheres Login',
        'products_search': 'Produktsuche',
        'how_it_works': 'Wie es funktioniert',
        'username': 'Benutzername',
        'password': 'Passwort',
        'login': 'Anmelden',
        'login_successful': 'Anmeldung erfolgreich! Willkommen, {}!',
        'admin_login': 'Sie sind als Administrator angemeldet!',
        'invalid_credentials': 'Ungültiger Benutzername oder Passwort!',
        'error': 'Fehler: {}',
        'search': 'Suchen',
        'sort_by': 'Sortieren nach',
        'id': 'ID',
        'name': 'Name',
        'price': 'Preis',
        'description': 'Beschreibung',
        'user_not_found': 'Benutzer nicht gefunden.',
        'provide_user_id': 'Bitte geben Sie eine Benutzer-ID an.',
        'understanding_sql_injection': 'SQL-Injection verstehen',
        'sql_injection_description': 'SQL-Injection ist eine Code-Injektionstechnik, die Sicherheitslücken in der Software einer Anwendung ausnutzt, indem bösartige SQL-Anweisungen in Eingabefelder eingefügt werden.',
        'common_techniques': 'Häufige SQL-Injection-Techniken',
        'auth_bypass': 'Authentifizierungsumgehung',
        'example': 'Beispiel:',
        'example_explanation': 'Wenn dies in ein Anmeldeformular injiziert wird:',
        'or_true_explanation': 'Das OR \'1\'=\'1\' wird immer als wahr ausgewertet, was dazu führt, dass die Abfrage unabhängig von Benutzername oder Passwort Ergebnisse zurückgibt.',
        'union_attack': 'UNION-basierte Angriffe',
        'union_explanation': 'UNION ermöglicht die Kombination von Ergebnissen aus mehreren SELECT-Anweisungen:',
        'union_example': '\' UNION SELECT username, password FROM users--',
        'union_result': 'Dies kann Daten aus anderen Tabellen in der Datenbank abrufen.',
        'blind_injection': 'Blinde SQL-Injection',
        'blind_explanation': 'Wird verwendet, wenn Fehlermeldungen unterdrückt werden:',
        'blind_example': '\' OR (SELECT 1 FROM users WHERE username=\'admin\' AND SUBSTR(password,1,1)=\'a\')=1--',
        'blind_result': 'Dies ermöglicht die Extraktion von Daten Zeichen für Zeichen basierend auf Wahr/Falsch-Bedingungen.',
        'language': 'Sprache',
        'detailed_explanation': 'Detaillierte Erklärung zur SQL-Injection',
        'prevention': 'Präventionsmaßnahmen',
        'param_queries': 'Parametrisierte Abfragen',
        'param_explanation': 'Verwenden Sie vorbereitete Anweisungen mit parametrisierten Abfragen, um SQL-Code von Daten zu trennen.',
        'input_validation': 'Eingabevalidierung',
        'validation_explanation': 'Implementieren Sie eine strenge Eingabevalidierung sowohl auf Client- als auch auf Serverseite.',
        'least_privilege': 'Prinzip der geringsten Privilegien',
        'privilege_explanation': 'Von Anwendungen verwendete Datenbankkonten sollten minimale Berechtigungen haben.',
        'escape_chars': 'Escapen von Sonderzeichen',
        'escape_explanation': 'Sonderzeichen in Benutzereingaben richtig escapen, bevor sie in SQL-Abfragen verwendet werden.',
        'orm': 'ORM-Frameworks verwenden',
        'orm_explanation': 'Object-Relational-Mapping-Frameworks bieten oft eingebauten Schutz gegen SQL-Injection.',
        'waf': 'Web Application Firewall',
        'waf_explanation': 'Implementieren Sie eine WAF, um bösartige SQL-Injection-Versuche zu filtern.',
        'db_details': 'Datenbankdetails',
        'table_structure': 'Tabellenstruktur',
        'users_table': 'Benutzertabelle',
        'products_table': 'Produkttabelle',
        'column': 'Spalte',
        'data_type': 'Datentyp',
        'primary_key': 'Primärschlüssel',
        'payload_examples': 'SQL-Injection-Payload-Beispiele',
        'vulnerability_types': 'Arten von SQL-Injection-Schwachstellen',
        'error_based': 'Fehlerbasiert',
        'time_based': 'Zeitbasiert',
        'out_of_band': 'Out-of-Band'
    }
}

def get_locale():
    # Get language from session or use default
    return session.get('language', 'en')

def get_text(key, *args):
    """Get translated text for a given key"""
    try:
        return TRANSLATIONS[get_locale()][key].format(*args)
    except (KeyError, IndexError):
        # Fallback to English if translation is missing
        try:
            return TRANSLATIONS['en'][key].format(*args)
        except (KeyError, IndexError):
            return f"Missing translation: {key}"

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
