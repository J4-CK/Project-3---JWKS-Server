from http.server import BaseHTTPRequestHandler, HTTPServer
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from urllib.parse import urlparse, parse_qs
import base64
import json
import jwt
import datetime
import os
import sqlite3
import uuid
from argon2 import PasswordHasher

# Create a global variable for the Argon2 hasher
ph = PasswordHasher()

# Define the path to the SQLite database file
DB_FILE = "totally_not_my_privateKeys.db"

# Import AES encryption related libraries
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# Set the AES key from environment variable
AES_KEY = os.getenv("NOT_MY_KEY")

hostName = "localhost"
serverPort = 8080

# Open or create SQLite database file
db_connection = sqlite3.connect(DB_FILE)
db_cursor = db_connection.cursor()

# Create keys table if it does not exist
db_cursor.execute('''CREATE TABLE IF NOT EXISTS keys(
                    kid INTEGER PRIMARY KEY AUTOINCREMENT,
                    key BLOB NOT NULL,
                    exp INTEGER NOT NULL
                    )''')

# Create auth_logs table if it does not exist
db_cursor.execute('''CREATE TABLE IF NOT EXISTS auth_logs(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    request_ip TEXT NOT NULL,
                    request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    user_id INTEGER,
                    FOREIGN KEY(user_id) REFERENCES users(id)
                    )''')

# Function to encrypt the private key using AES
def encrypt_private_key(key):
    backend = default_backend()
    cipher = Cipher(algorithms.AES(AES_KEY.encode()), modes.ECB(), backend=backend)
    encryptor = cipher.encryptor()
    cipher_text = encryptor.update(key) + encryptor.finalize()
    return cipher_text

# Function to store keys in the database
def store_key_in_db(key, exp):
    # Encrypt the private key using AES
    encrypted_key = encrypt_private_key(key)
    db_cursor.execute("INSERT INTO keys(key, exp) VALUES (?, ?)", (encrypted_key, exp))
    db_connection.commit()

# Function to create the users table if it does not exist
def create_users_table():
    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()
        cursor.execute('''CREATE TABLE IF NOT EXISTS users(
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            username TEXT NOT NULL UNIQUE,
                            password_hash TEXT NOT NULL,
                            email TEXT UNIQUE,
                            date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                            last_login TIMESTAMP      
                        )''')

# Function to handle user registration
def register_user(username, email):
    # Generate a secure password for the user using UUIDv4
    password = str(uuid.uuid4())
    
    # Hash the password using Argon2 with configurable settings
    hashed_password = ph.hash(password)
    
    # Store the user details and hashed password in the users table
    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()
        cursor.execute('''INSERT INTO users(username, password_hash, email) 
                          VALUES (?, ?, ?)''', (username, hashed_password, email))
        conn.commit()

class MyServer(BaseHTTPRequestHandler):
    # Implement other methods as before

    # Implement a rate limiter for POST:/auth endpoint
    AUTH_REQUESTS = {}
    RATE_LIMIT = 10  # Limit requests to 10 per second

    def do_POST(self):
        parsed_path = urlparse(self.path)
        params = parse_qs(parsed_path.query)
        if parsed_path.path == "/auth":
            # Implement rate limiter
            request_ip = self.client_address[0]
            current_time = datetime.datetime.now().timestamp()

            if request_ip not in self.AUTH_REQUESTS:
                self.AUTH_REQUESTS[request_ip] = [current_time]
            else:
                request_times = self.AUTH_REQUESTS[request_ip]
                request_times = [t for t in request_times if current_time - t < 1]
                if len(request_times) >= self.RATE_LIMIT:
                    self.send_response(429)
                    self.end_headers()
                    return
                else:
                    request_times.append(current_time)
                    self.AUTH_REQUESTS[request_ip] = request_times
            
            # Log authentication requests
            self.log_authentication_request(request_ip)
            
            # Implement authentication logic
            pass
        elif parsed_path.path == "/register":
            # Implement user registration logic
            pass
        else:
            self.send_response(405)
            self.end_headers()
            return

    def do_GET(self):
        if self.path == "/.well-known/jwks.json":
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            keys = {
                "keys": []
            }
            # Retrieve valid (non-expired) keys from database
            db_cursor.execute("SELECT key, kid FROM keys WHERE exp >= ?", (datetime.datetime.utcnow(),))
            rows = db_cursor.fetchall()
            for row in rows:
                # Decrypt the private key using AES
                backend = default_backend()
                cipher = Cipher(algorithms.AES(AES_KEY.encode()), modes.ECB(), backend=backend)
                decryptor = cipher.decryptor()
                private_key = decryptor.update(row[0]) + decryptor.finalize()

                private_key = serialization.load_pem_private_key(private_key, password=None)
                key_dict = {
                    "alg": "RS256",
                    "kty": "RSA",
                    "use": "sig",
                    "kid": f"key_{row[1]}",
                    "n": bytes_to_base64(private_key.public_key().public_numbers().n.to_bytes(256, 'big')),
                    "e": bytes_to_base64(private_key.public_key().public_numbers().e.to_bytes(3, 'big')),
                }
                keys["keys"].append(key_dict)
            self.wfile.write(bytes(json.dumps(keys), "utf-8"))
            return

    def log_authentication_request(self, request_ip):
        # Log authentication requests into the auth_logs table
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute('''INSERT INTO auth_logs(request_ip, user_id) 
                              VALUES (?, ?)''', (request_ip, None))
            conn.commit()

if __name__ == "__main__":
    # Create users table if it does not exist
    create_users_table()

    # Start the HTTP server
    webServer = HTTPServer((hostName, serverPort), MyServer)
    try:
        webServer.serve_forever()
    except KeyboardInterrupt:
        pass

    webServer.server_close()
