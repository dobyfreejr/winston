import json
import logging
import os
import re
import secrets
import socket
import requests
from flask import Flask, render_template, request, redirect, url_for, session
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.utils import secure_filename
from dotenv import load_dotenv
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired
from flask_wtf import CSRFProtect
# Load environment variables
load_dotenv()

# Initialize Flask app
app = Flask(__name__)
app.secret_key = secrets.token_urlsafe(16)  # Secure session
csrf = CSRFProtect(app)

class VirusTotalForm(FlaskForm):
    hash_value = StringField('Enter Hash Value:', validators=[DataRequired()])
    submit = SubmitField('Search VirusTotal')

class IPForm(FlaskForm):
    ip_address = StringField('Enter IP Address:', validators=[DataRequired()])
    submit = SubmitField('Lookup IP')

class DomainForm(FlaskForm):
    domain = StringField('Enter Domain:', validators=[DataRequired()])
    submit = SubmitField('Search Whois')

class UploadForm(FlaskForm):
    file = StringField('Upload Malware Sample', validators=[DataRequired()])
    submit = SubmitField('Upload to MalwareBazaar')

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logging.getLogger().setLevel(logging.DEBUG)

# Flask-Login setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.session_protection = "strong"

# Upload settings
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'exe', 'zip', 'rar', 'tar', 'gz'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Ensure upload directory exists
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# CSRF-protected logout form class
class LogoutForm(FlaskForm):
    submit = SubmitField('Logout')

# Helper function to get real client IP
def get_user_ip():
    return request.headers.get('X-Forwarded-For', request.remote_addr)

# Ensure the upload folder exists
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')
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
@app.route('/virustotal_lookup', methods=['POST'])
@login_required
def virustotal_route():
    logging.debug("Accessed VirusTotal lookup route")
    hash_value = request.form.get("hash_value")
    if not hash_value:
        return render_template("error.html", error='Hash value field is empty'), 400

    base_url = "https://www.virustotal.com/api/v3/files"
    headers = {"x-apikey": os.getenv("VIRUSTOTAL_API_KEY")}

    def safe_get(endpoint):
        try:
            resp = requests.get(endpoint, headers=headers)
            if resp.status_code == 200:
                return resp.json()
            else:
                logging.warning(f"{endpoint} returned {resp.status_code}")
                return None
        except Exception as e:
            logging.error(f"Failed to fetch {endpoint}: {str(e)}")
            return None

    result = {
        'file': safe_get(f"{base_url}/{hash_value}"),
        'behavior': safe_get(f"{base_url}/{hash_value}/behaviour"),  # may return 404
        'ips': safe_get(f"{base_url}/{hash_value}/contacted_ips"),
        'urls': safe_get(f"{base_url}/{hash_value}/contacted_urls"),
        'relationships': safe_get(f"{base_url}/{hash_value}/relationships"),
        'comments': safe_get(f"{base_url}/{hash_value}/comments"),
        'votes': safe_get(f"{base_url}/{hash_value}/votes"),
        'sandbox_verdicts': safe_get(f"{base_url}/{hash_value}/sandbox_verdicts"),
    }

    if not result['file'] or 'data' not in result['file']:
        return render_template("error.html", error="Invalid or missing data for file hash"), 400

    return render_template("virustotal_result.html", hash_value=hash_value, result=result)

def get_abuseipdb_data(ip_address):
    try:
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {
            "Key": os.getenv("ABUSEIPDB_API_KEY"),
            "Accept": "application/json"
        }
        params = {
            "ipAddress": ip_address,
            "maxAgeInDays": 90,
            "verbose": True
        }

        response = requests.get(url, headers=headers, params=params, timeout=10)
        response.raise_for_status()

        return response.json().get("data", {})
    except Exception as e:
        logging.error(f"AbuseIPDB request failed for {ip_address}: {str(e)}")
        return None
def perform_ip_lookup(ip_address):
    try:
        url = f"https://ipinfo.io/{ip_address}/json"
        response = requests.get(url, timeout=10)

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
            logging.warning(f"IPInfo request failed for {ip_address}: {response.status_code}")
            return None
    except Exception as e:
        logging.error(f"IPInfo lookup error for {ip_address}: {str(e)}")
        return None

# Define the function to perform IP lookup
@app.route('/ip_lookup', methods=['POST'])
@login_required
def ip_lookup_route():
    logging.debug("Accessed IP lookup route")
    ip_address = request.form.get("ip_address")
    if not ip_address:
        logging.debug("IP address field is empty")
        return render_template("error.html", error='IP address field is empty'), 400

    ip_info = perform_ip_lookup(ip_address)

    if not ip_info:
        logging.debug("Unable to fetch IP information from ipinfo")
        return render_template("error.html", error='Unable to fetch IP information'), 400

    abuse_info = get_abuseipdb_data(ip_address)

    return render_template("ip_result.html", ip_info=ip_info, abuse_info=abuse_info)



def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def upload_to_malwarebazaar(file_path, anonymous=1, delivery_method='email_attachment', tags=None, references=None, context=None):
    try:
        api_key = ''  # Replace with your API key
        url = 'https://mb-api.abuse.ch/api/v1/'

        headers = {'API-KEY': api_key}

        # Prepare JSON data based on function parameters
        data = {
            'anonymous': anonymous,
            'delivery_method': delivery_method,
            'tags': tags if tags else [],
            'references': references if references else {},
            'context': context if context else {}
        }

        files = {
            'json_data': (None, json.dumps(data), 'application/json'),
            'file': (open(file_path, 'rb'))
        }

        response = requests.post(url, files=files, headers=headers, verify=False)

        logging.debug(f"MalwareBazaar response status code: {response.status_code}")
        logging.debug(f"MalwareBazaar response content: {response.text}")

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
    form = LoginForm()

    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        logging.debug(f"Received login credentials: username='{username}'")

        if username == 'admin' and password == 'admin':
            logging.debug("Valid credentials, setting session")
            user = User(username)
            login_user(user)
            session['username'] = username
            return redirect(url_for('index_after_login'))
        else:
            error = 'Invalid username or password'
            logging.debug("Invalid credentials")
            return render_template('login.html', form=form, error=error)

    # Render login page for GET or invalid form
    return render_template('login.html', form=form)



# Route for the index page after login
@app.route('/index_after_login')
@login_required
def index_after_login():
    logging.debug("Accessed index_after_login route")
    return render_template(
        'index.html',
        vt_form=VirusTotalForm(),
        ip_form=IPForm(),
        domain_form=DomainForm(),
        upload_form=UploadForm(),
        logout_form=LogoutForm()
    )


@app.route('/logout', methods=['POST'])
@login_required
def logout():
    user = current_user.get_id()
    ip = get_user_ip()
    logging.info(f"[LOGOUT] User '{user}' logged out from IP {ip}")

    logout_user()
    session.pop('username', None)
    return redirect(url_for("login"))


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


# Route for the file upload
@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload():
    if request.method == 'POST':
        if 'file' not in request.files:
            return 'No file part', 400
        file = request.files['file']
        if file.filename == '':
            return 'No selected file', 400
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)
            logging.debug(f"File saved: {file_path}")
            return 'File uploaded successfully', 200
    return render_template('upload.html')


# Route for uploading to MalwareBazaar
@app.route('/upload_to_malwarebazaar', methods=['POST'])
@login_required
def upload_to_malwarebazaar_route():
    file = request.files['file']
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)
        logging.debug(f"File saved: {file_path}")

        # Prepare parameters for MalwareBazaar upload
        anonymous = request.form.get('anonymous', '1')  # Default to anonymous
        delivery_method = request.form.get('delivery_method', 'email_attachment')
        tags = request.form.getlist('tags')
        references = request.form.get('references')
        context = request.form.get('context')

        # Call the upload function
        response = upload_to_malwarebazaar(file_path, anonymous, delivery_method, tags, references, context)
        return render_template("upload_result.html", response=response)
    return render_template("error.html", error='Invalid file'), 400

def get_abuseipdb_data(ip_address):
    try:
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {
            "Key": os.getenv("ABUSEIPDB_API_KEY"),
            "Accept": "application/json"
        }
        params = {
            "ipAddress": ip_address,
            "maxAgeInDays": 90,
            "verbose": True
        }

        response = requests.get(url, headers=headers, params=params, timeout=10)
        response.raise_for_status()

        return response.json().get("data", {})
    except Exception as e:
        logging.error(f"AbuseIPDB request failed for {ip_address}: {str(e)}")
        return None

if __name__ == '__main__':
    app.run(debug=True)  # Change debug to False in production
