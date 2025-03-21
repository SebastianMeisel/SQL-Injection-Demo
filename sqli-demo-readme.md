# SQL Injection Demo Application

This is a deliberately vulnerable web application designed to demonstrate how SQL injection attacks work and how to prevent them. It uses a Flask web server with a SQLite database.

## ⚠️ Warning

This application contains intentional security vulnerabilities for educational purposes only. Do not deploy this in a production environment or expose it to the internet.

## Directory Structure

Create the following directory structure:

```
sqli-demo/
│
├── app/
│   ├── app.py
│   ├── requirements.txt
│   ├── templates/
│   │   ├── index.html
│   │   ├── login.html
│   │   ├── login_safe.html
│   │   ├── products.html
│   │   ├── user.html
│   │   └── how_it_works.html
│   └── database.db (will be created automatically)
│
├── Dockerfile
└── docker-compose.yml
```

## Setup Instructions

1. Create the directory structure as shown above
2. Copy each file from the provided artifacts into its respective location
3. Build and start the Docker container:

```bash
cd sqli-demo
docker-compose up --build
```

4. Access the application in your browser at: http://localhost:5000

## SQL Injection Demo Scenarios

The application demonstrates the following SQL injection vulnerabilities:

### 1. Authentication Bypass

URL: http://localhost:5000/login

Try entering:
- Username: `' OR '1'='1`
- Password: anything

This will bypass the authentication and log you in as the first user (admin).

### 2. Data Extraction using ORDER BY

URL: http://localhost:5000/products

Try selecting this in the "Sort By" dropdown:
- `id, (SELECT password FROM users WHERE is_admin=1)`

This will display the admin password in the sorting order.

### 3. Data Extraction using UNION

URL: http://localhost:5000/users?id=1

Try changing the URL to:
- http://localhost:5000/users?id=1 UNION SELECT 'Injected', group_concat(username || ':' || password) FROM users

This will display all usernames and passwords from the database.

## Safe Alternatives

The application also demonstrates how to prevent SQL injection:

- Parameterized queries (see the safe login form)
- Input validation
- Proper error handling

## Learning Resources

For more information about SQL injection and how to prevent it, check out:

- [OWASP SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection)
- [OWASP SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- [PortSwigger SQL Injection Tutorial](https://portswigger.net/web-security/sql-injection)
