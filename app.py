from flask import Flask, render_template, request, jsonify
import logging
import socket
import re
import requests

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.DEBUG)

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

# Define the route for the index page
@app.route('/')
def index():
    return render_template('index.html')

# Define the route for the WHOIS lookup form submission
@app.route('/lookup', methods=['POST'])
def lookup():
    domain = request.form.get("domain")
    if not domain:
        return "Error: Domain field is empty", 400
    result = whois_lookup(domain)
    parsed_result = parse_whois_result(result)
    return render_template("result.html", domain=domain, whois_result=parsed_result)

# Define the route for the VirusTotal lookup form submission
@app.route('/virustotal/lookup', methods=['POST'])
def virustotal_lookup_route():
    hash_value = request.form.get("hash_value")
    if not hash_value:
        return "Error: Hash value field is empty", 400
    result = virustotal_lookup(hash_value)
    return jsonify(result) if isinstance(result, dict) else result, 200 if isinstance(result, dict) else 500

# Run the Flask app
if __name__ == '__main__':
    app.run(debug=True)
