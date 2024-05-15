import re
import socket
import logging
import secrets
import requests
from flask import Flask, render_template, request, redirect, url_for, session
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.utils import secure_filename
import os

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

# Set upload folder and allowed extensions
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = set()

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER


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
        api_key = ''  # Replace with your actual
        # VirusTotal API key
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


# Define the function to perform IP lookup
def ip_lookup(ip_address):
    url = f"https://ipinfo.io/{ip_address}/json"
    response = requests.get(url)

    if response.status_code == 200:
        data = response.json()
        ip_info = {
            "IP Address": data.get("ip"),
            "Hostname": data.get("hostname", "N/A"),
            "City": data.get("city", "N/A"),
            "Region": data.get("region", "N/A"),
            "Country": data.get("country", "N/A"),
            "Location": data.get("loc", "N/A"),
            "Organization": data.get("org", "N/A")
        }
        return ip_info
    else:
        return None


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def upload_to_malwarebazaar(file_path):
    try:
        api_key = ''  # Replace with your MalwareBazaar API key
        url = 'https://mb-api.abuse.ch/api/v1/'
        files = {'file': open(file_path, 'rb')}
        data = {'apikey': api_key, 'anonymous': '0'}
        response = requests.post(url, files=files, data=data)

        if response.status_code == 200:
            result = response.json()
            return result
        else:
            return f"Error: Unable to upload sample to MalwareBazaar (Status code: {response.status_code})"
    except Exception as e:
        logging.error(f"Error occurred during MalwareBazaar upload: {str(e)}")
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


# Route for the IP lookup form submission
@app.route('/ip_lookup', methods=['POST'])
@login_required
def ip_lookup_route():
    logging.debug("Accessed IP lookup route")
    ip_address = request.form.get("ip_address")
    if not ip_address:
        logging.debug("IP address field is empty")
        return render_template("error.html", error='IP address field is empty'), 400
    # Perform IP lookup
    ip_info = ip_lookup(ip_address)
    if ip_info:
        return render_template("ip_result.html", ip_address=ip_address, ip_info=ip_info)
    else:
        error_msg = f"Failed to retrieve information for the IP address: {ip_address}"
        logging.error(error_msg)
        return render_template("error.html", error=error_msg), 500


# Route for handling VirusTotal hash lookup
@app.route('/virustotal_lookup', methods=['POST'])
@login_required
def virustotal_lookup_route():
    logging.debug("Accessed VirusTotal lookup route")
    hash_value = request.form.get("hash_value")
    if not hash_value:
        logging.debug("Hash value field is empty")
        return render_template("error.html", error='Hash value field is empty'), 400
    # Perform VirusTotal lookup
    result = virustotal_lookup(hash_value)
    return render_template("virustotal_result.html", hash_value=hash_value, result=result)


# Route for malware sample upload
# Update file upload route to handle any file type
@app.route('/upload_malware_sample', methods=['GET', 'POST'])
@login_required
def upload_malware_sample():
    logging.debug("Accessed upload malware sample route")

    if request.method == 'POST':
        if 'file' not in request.files:
            logging.debug("No file part in the request")
            return render_template("error.html", error='No file part in the request'), 400

        file = request.files['file']

        if file.filename == '':
            logging.debug("No selected file")
            return render_template("error.html", error='No selected file'), 400

        if file:
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)

            # Upload to MalwareBazaar and retrieve results
            result = upload_to_malwarebazaar(file_path)
            os.remove(file_path)  # Remove file after uploading

            return render_template("malwarebazaar_result.html", result=result)
        else:
            logging.debug("File type not allowed")
            return render_template("error.html", error='File type not allowed'), 400

    return render_template("upload.html")

# Run the Flask app
if __name__ == '__main__':
    app.run(debug=True)
