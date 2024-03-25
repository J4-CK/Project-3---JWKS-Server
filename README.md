# Project-2---JWKS-Server
JWKS Server with SQLite Database
This is a Python-based JSON Web Key Set (JWKS) server with SQLite database integration. It allows you to serve public keys with expiry and unique key identifiers (kid) for verifying JSON Web Tokens (JWTs). The server stores private keys in an SQLite database, ensuring persistence and availability even after server restarts.

Requirements
Python 3.x
Required Python packages:
cryptography
http.server
urllib.parse
base64
json
jwt
sqlite3
Usage
Installation:

Ensure you have Python 3.x installed on your system.
Install the required Python packages listed above using pip install <package_name>.
Running the Server:

Open a terminal or command prompt.
Navigate to the directory containing the my_server.py file.
Run the server by executing the command:
Copy code
python my_server.py
The server will start running on localhost at port 8080 by default.
Endpoints:

Authentication Endpoint (/auth):

Sends a JWT signed with a private key stored in the database.
To obtain a JWT, send a POST request to /auth.
Example: POST http://localhost:8080/auth
JWKS Endpoint (/.well-known/jwks.json):

Retrieves valid (non-expired) public keys from the database and serves them as a JWKS.
To retrieve the JWKS, send a GET request to /.well-known/jwks.json.
Example: GET http://localhost:8080/.well-known/jwks.json
Database:

The server uses an SQLite database named totally_not_my_privateKeys.db to store private keys.
The database file will be automatically created in the same directory where the server script (my_server.py) is located.
Testing:

Use tools like cURL, Postman, or your preferred HTTP client to send requests to the server and test its functionality.
