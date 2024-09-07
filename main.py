import sqlite3
import hashlib

conn = sqlite3.connect('credentials.db')
cursor = conn.cursor()

cursor.execute('''
CREATE TABLE IF NOT EXISTS users (
    login TEXT PRIMARY KEY,
    password TEXT NOT NULL
)
''')
conn.commit()

def hash_data(data):
    hash_object = hashlib.sha256()
    hash_object.update(data.encode('utf-8'))
    hash_hex = hash_object.hexdigest()
    return hash_hex

def sign_in():
    def add_login():
        while True:
            login = input("login: ")
            cursor.execute('SELECT * FROM users WHERE login = ?', (login,))
            if cursor.fetchone():
                print("The login has been already taken by another user.")
            else:
                break
        return login

    login = add_login()
    while True:
        password = input("password: ")
        password_confirm = input("Confirm your password: ")
        if password == password_confirm:
            password_hash = hash_data(password)
            cursor.execute('INSERT INTO users (login, password) VALUES (?, ?)', (login, password_hash))
            conn.commit()
            print("User registered successfully.")
            break

def log_in():
    login = None
    while True:
        login = input("login: ")
        cursor.execute('SELECT password FROM users WHERE login = ?', (login,))
        result = cursor.fetchone()
        if result:
            password_hash = result[0]
            break
        else:
            print("Login not found. Please try again.")

    while True:
        password = input("password: ")
        if hash_data(password) == password_hash:
            print(f"Login successful. Welcome, {login}!")
            break
        else:
            print("Incorrect password. Please try again.")

sign_in()
log_in()
