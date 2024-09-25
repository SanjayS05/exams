# exams
SQL injection
{
Attack:
import sqlite3

# Connect to the database
conn = sqlite3.connect('example.db')
cursor = conn.cursor()

# Vulnerable function where user input is directly added to the SQL query
def get_user_by_username(username):
    query = f"SELECT * FROM users WHERE username = '{username}'"
    cursor.execute(query)
    return cursor.fetchall()

# Example usage (dangerous input can be used for SQL injection)
user_input = input("Enter username: ")  # e.g., ' OR '1'='1
result = get_user_by_username(user_input)
print(result)

conn.close()

Def:
import sqlite3

# Connect to the database
conn = sqlite3.connect('example.db')
cursor = conn.cursor()

# Secure function with parameterized queries
def get_user_by_username(username):
    query = "SELECT * FROM users WHERE username = ?"
    cursor.execute(query, (username,))
    return cursor.fetchall()

# Example usage (safe from SQL injection)
user_input = input("Enter username: ")
result = get_user_by_username(user_input)
print(result)

conn.close()

}

XSS
{
Attack:
from http.server import BaseHTTPRequestHandler, HTTPServer
import urllib

class XSSVulnerableServer(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        
        # Retrieve the user input from the query string
        query = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        user_input = query.get('input', [''])[0]  # Vulnerable to XSS
        
        # Render the input directly in the response (unsafe)
        response = f"""
        <html>
            <body>
                <h1>Search Result</h1>
                <p>You searched for: {user_input}</p>
            </body>
        </html>
        """
        self.wfile.write(response.encode('utf-8'))

if __name__ == "__main__":
    server_address = ('', 8080)
    httpd = HTTPServer(server_address, XSSVulnerableServer)
    print("Starting server at http://localhost:8080")
    httpd.serve_forever()

Def:
from http.server import BaseHTTPRequestHandler, HTTPServer
import urllib
import html

class XSSSafeServer(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        
        # Retrieve the user input from the query string
        query = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        user_input = query.get('input', [''])[0]

        # Sanitize the user input to prevent XSS (escaping dangerous characters)
        safe_input = html.escape(user_input)
        
        # Render the safe input in the response
        response = f"""
        <html>
            <body>
                <h1>Search Result</h1>
                <p>You searched for: {safe_input}</p>
            </body>
        </html>
        """
        self.wfile.write(response.encode('utf-8'))

if __name__ == "__main__":
    server_address = ('', 8080)
    httpd = HTTPServer(server_address, XSSSafeServer)
    print("Starting server at http://localhost:8080")
    httpd.serve_forever()
}

CSRF
{
Attack:

Def:
}
