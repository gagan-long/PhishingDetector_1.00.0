from flask import Flask, request, render_template
from urllib.parse import urlparse
import re

app = Flask(__name__)

def extract_url_details(url):
    details = {}
    parsed_url = urlparse(url)

    details['url_length'] = len(url)
    details['has_ip'] = 'Yes' if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', parsed_url.netloc) else 'No'
    details['has_login'] = 'Yes' if 'login' in parsed_url.path.lower() or 'login' in parsed_url.netloc.lower() else 'No'
    details['domain'] = parsed_url.netloc

    return details

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        url = request.form['url']
        prediction = "Phishing"  # Placeholder prediction
        details = extract_url_details(url)

        return render_template('result.html', url=url, prediction=prediction, details=details)
    return render_template('index.html')

if __name__ == '__main__':
    app.run(debug=True)
