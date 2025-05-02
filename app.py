from flask import Flask, request, render_template
from urllib.parse import urlparse
import re
import whois
import ssl
import requests
import socket
from bs4 import BeautifulSoup
import json
from urllib.parse import urljoin
from concurrent.futures import ThreadPoolExecutor


app = Flask(__name__)

# Load Blacklist Data
try:
    with open('blacklist.json', 'r') as f:
        blacklisted_domains = json.load(f)
except FileNotFoundError:
    blacklisted_domains = []

def calculate_risk_score(details):
    score = 0
    if details['has_at_symbol'] == 'Yes':
        score += 5
    if details['url_length'] > 50:
        score += 10
    if details['uses_https'] == 'No':
        score += 15
    if details['domain_age'] == 'N/A':
        score += 10
    if details['has_ip_address'] == 'Yes':
        score += 20
    if details['has_login_form'] == 'Yes':
        score += 25
    if details['requests_sensitive_info'] == 'Yes':
        score += 30
    if details['has_unusual_scripts'] == 'Yes':
        score += 20
    
    return score

def extract_details(url):
    details = {}
    try:
        parsed_url = urlparse(url)

        # Presence of "@" in URL
        details['has_at_symbol'] = 'Yes' if '@' in url else 'No'

        # Length of URL
        details['url_length'] = len(url)

         # Add crawling results
        details['found_paths'] = crawl_website(url)

        # Use of HTTPS
        details['uses_https'] = 'Yes' if parsed_url.scheme == 'https' else 'No'

        # Domain age and Registrar (WHOIS information)
        domain = parsed_url.netloc
        try:
            w = whois.whois(domain)
            details['domain_age'] = str(w.creation_date)
            details['registrar'] = w.registrar if hasattr(w, 'registrar') else 'N/A'
        except Exception as e:
            details['whois_error'] = str(e)
            details['domain_age'] = 'N/A'
            details['registrar'] = 'N/A'

        # SSL Certificate Information
        if parsed_url.scheme == 'https':
            try:
                context = ssl.create_default_context()
                with socket.create_connection((domain, 443), timeout=5) as sock:
                    with context.wrap_socket(sock, server_hostname=domain) as ssock:
                        cert = ssock.getpeercert()
                        details['ssl_issuer'] = cert.get('issuer', 'N/A')
                        details['ssl_valid'] = str(cert.get('notAfter', 'N/A'))
            except Exception as e:
                details['ssl_error'] = str(e)
                details['ssl_issuer'] = 'N/A'
                details['ssl_valid'] = 'N/A'
        else:
            details['ssl_issuer'] = 'N/A'
            details['ssl_valid'] = 'N/A'

        # Favicon Analysis (Check if favicon exists)
        try:
            response = requests.get(parsed_url.scheme + '://' + parsed_url.netloc + '/favicon.ico', timeout=5)
            details['has_favicon'] = 'Yes' if response.status_code == 200 else 'No'
        except Exception as e:
            details['favicon_error'] = str(e)
            details['has_favicon'] = 'No'

        # URL Analysis
        details['has_ip_address'] = 'Yes' if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', parsed_url.netloc) else 'No'
        details['is_long_url'] = 'Yes' if len(url) > 50 else 'No'
        details['has_unusual_chars'] = 'Yes' if re.search(r'[^a-zA-Z0-9\-\._~:\/\?#\[\]@!\$&\'\(\)\*\+\,\;\=]', url) else 'No'

        # Website Content Analysis (basic, looking for login form and sensitive info)
        try:
            response = requests.get(url, timeout=5)
            soup = BeautifulSoup(response.text, 'html.parser')

            # Looking for login form
            login_form = soup.find('form', {'action': re.compile(r'login', re.IGNORECASE)})
            details['has_login_form'] = 'Yes' if login_form else 'No'

            # Looking for requests for sensitive information (e.g., credit card, social security number)
            sensitive_info_patterns = [r'credit card', r'social security number', r'ssn', r'cvv']
            content = soup.get_text().lower()
            has_sensitive_info_request = any(re.search(pattern, content) for pattern in sensitive_info_patterns)
            details['requests_sensitive_info'] = 'Yes' if has_sensitive_info_request else 'No'

            # Looking for unusual scripts (e.g., obfuscated JavaScript)
            script_tags = soup.find_all('script')
            unusual_scripts = any('eval(' in script.text for script in script_tags)
            details['has_unusual_scripts'] = 'Yes' if unusual_scripts else 'No'

        except Exception as e:
            details['content_error'] = str(e)
            details['has_login_form'] = 'N/A'
            details['requests_sensitive_info'] = 'N/A'
            details['has_unusual_scripts'] = 'N/A'
            
        # Blacklist Checking
        details['is_blacklisted'] = 'Yes' if domain in blacklisted_domains else 'No'

    except Exception as e:
        details['error'] = str(e)
    return details

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        url = request.form['url']
        details = extract_details(url)
        risk_score = calculate_risk_score(details)
        
        # Suggest a prediction based on the risk score
        if risk_score > 50:
            prediction = "Highly Likely Phishing"
        elif risk_score > 30:
            prediction = "Likely Phishing"
        else:
            prediction = "Potentially Safe"

        return render_template('result.html', url=url, prediction=prediction, details=details, risk_score=risk_score)
    return render_template('index.html')

@app.route('/feedback', methods=['POST'])
def feedback():
    url = request.form['url']
    feedback = request.form['feedback']
    # For now, let's just print the feedback (later we can save it to a file or database)
    print(f"Feedback for {url}: {feedback}")
    return "Thank you for your feedback!"

def crawl_website(target_url):
    base_url = f"{urlparse(target_url).scheme}://{urlparse(target_url).netloc}"
    session = requests.Session()
    found_paths = set(['/'])
    
    def check_path(path):
        try:
            full_url = urljoin(base_url, path)
            response = session.head(full_url, timeout=3, allow_redirects=True)
            if response.status_code < 400:
                return path
        except:
            return None
    
    # Common directory list
    common_dirs = [
        'admin', 'login', 'wp-admin', 'wp-content', 
        'images', 'css', 'js', 'assets', 'uploads',
        'backup', 'api', 'secret', 'private', ''
    ]
    
    # Common file list
    common_files = [
        'robots.txt', 'sitemap.xml', 'config.php',
        '.env', 'package.json', 'web.config', '.venv', 'index.php'
    ]
    
    with ThreadPoolExecutor(max_workers=10) as executor:
        # Check directories
        dir_paths = [f"/{d}/" for d in common_dirs]
        found_paths.update(filter(None, executor.map(check_path, dir_paths)))
        
        # Check files
        file_paths = [f"/{f}" for f in common_files]
        found_paths.update(filter(None, executor.map(check_path, file_paths)))
    
    return sorted(found_paths)

if __name__ == '__main__':
    app.run(debug=True)
