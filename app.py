import logging
import re
import socket
import os
import secrets
import requests
from flask import Flask, render_template, request, redirect, url_for, session
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user


app = Flask(__name__, template_folder='templates')

app.secret_key = secrets.token_urlsafe(16)  # Generate a secure secret key

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logging.getLogger().setLevel(logging.DEBUG)

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.session_protection = "strong"

# Define a User class for Flask-Login
class User(UserMixin):
    def __init__(self, username):
        self.id = username

    def is_authenticated(self):
        return True

    def is_active(self):
        return True

    def is_anonymous(self):
        return False

    def get_id(self):
        return self.id

# Set the current user based on the session
@login_manager.user_loader
def load_user(username):
    if username == 'admin':
        return User(username)
    return None

# Define the function to get the WHOIS server for a given domain
def get_whois_server(domain):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect(("whois.iana.org", 43))
            s.sendall((domain + "\r\n").encode())
            data = b""
            while True:
                partial_data = s.recv(1024)
                if not partial_data:
                    break
                data += partial_data
        response = data.decode()
        match = re.search(r"whois:\s+(.+)", response, re.IGNORECASE)
        if match:
            return match.group(1).strip()
        else:
            return None
    except Exception as e:
        logging.error(f"Error occurred while getting WHOIS server for domain '{domain}': {str(e)}")
        return None

# Define the function to perform a WHOIS lookup for a specific domain
def whois_lookup(domain):
    try:
        whois_server = get_whois_server(domain)
        if not whois_server:
            return "Error: Unable to determine WHOIS server for domain"
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((whois_server, 43))
            s.sendall((domain + "\r\n").encode())
            data = b""
            while True:
                partial_data = s.recv(1024)
                if not partial_data:
                    break
                data += partial_data
        result = data.decode()
        logging.debug(f"WHOIS response for domain '{domain}': {result}")
        return result
    except Exception as e:
        logging.error(f"Error occurred during WHOIS lookup for domain '{domain}': {str(e)}")
        return str(e)

# Define the function to parse WHOIS results
def parse_whois_result(whois_result):
    parsed_result = {}
    lines = whois_result.split('\n')
    for line in lines:
        if ':' in line:
            key, value = line.split(':', 1)
            key = key.strip()
            value = value.strip()
            if key in parsed_result:
                if isinstance(parsed_result[key], list):
                    parsed_result[key].append(value)
                else:
                    parsed_result[key] = [parsed_result[key], value]
            else:
                parsed_result[key] = value
    return parsed_result

# Define the function to perform a VirusTotal lookup
def virustotal_lookup(hash_value):
    try:
        api_key = ''  # Replace with your actual VirusTotal API key
        url = f'https://www.virustotal.com/api/v3/files/{hash_value}'
        headers = {'x-apikey': api_key}
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            result = response.json()
            return result
        else:
            return f"Error: Unable to perform VirusTotal lookup (Status code: {response.status_code})"
    except Exception as e:
        logging.error(f"Error occurred during VirusTotal lookup for hash value '{hash_value}': {str(e)}")
        return str(e)

# Route for the index page
@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('index_after_login'))
    return redirect(url_for('login'))

# Route for rendering the login page
@app.route('/login', methods=['GET', 'POST'])
def login():
    logging.debug("Accessed login route")
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        logging.debug(f"Received login credentials: username='{username}', password='{password}'")
        # Basic authentication, replace with secure authentication method
        if username == 'admin' and password == 'admin':
            logging.debug("Valid credentials, setting session")
            user = User(username)
            login_user(user)
            session['username'] = username
            return redirect(url_for('index_after_login'))
        else:
            error = 'Invalid username or password'
            logging.debug("Invalid credentials")
            return render_template('login.html', error=error)
    # Render login page for GET request
    logging.debug("Rendering login page")
    return render_template('login.html')

# Route for the index page after login
@app.route('/index_after_login')
@login_required
def index_after_login():
    logging.debug("Accessed index_after_login route")
    return render_template('index.html')

# Route for logging out
@app.route('/logout', methods=['GET'])  # Allow only GET requests
@login_required
def logout():
    logging.debug("Accessed logout route")
    logout_user()
    session.pop('username', None)
    logging.debug("User logged out, redirecting to login page")  # Updated log message
    return redirect(url_for("login"))  # Redirect to the login page

# Route for the WHOIS lookup form submission
@app.route('/lookup', methods=['POST'])
@login_required
def lookup():
    logging.debug("Accessed lookup route")
    domain = request.form.get("domain")
    if not domain:
        logging.debug("Domain field is empty")
        return render_template("error.html", error='Domain field is empty'), 400
    # Perform WHOIS lookup
    result = whois_lookup(domain)
    parsed_result = parse_whois_result(result)
    return render_template("result.html", domain=domain, whois_result=parsed_result)

# Run the Flask app
if __name__ == '__main__':
    app.run(debug=True)

