from flask import Flask, render_template, request
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse

app = Flask(__name__)


def validate_url(user_input):
    url = user_input.strip()

    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url

    parsed = urlparse(url)

    if parsed.scheme not in ['http', 'https']:
        return None, "Invalid URL scheme. Only HTTP and HTTPS are allowed."

    if '.' not in parsed.netloc:
        return None, "Invalid domain name."

    forbidden_hosts = ['localhost', '127.0.0.1', '0.0.0.0', '::1']
    if parsed.netloc.split(':')[0] in forbidden_hosts:
        return None, "Scanning local resources is not allowed."

    return url, None


def scan_website(url):
    results = {
        "score": 0,
        "https": False,
        "hsts": False,
        "clickjacking": False,
        "mime_sniffing": False,
        "server_hidden": True,
        "cookies_secure": "No cookies found",
        "cookies_score": 0,
        "response_time": 0,
        "speed_rating": "N/A",
        "has_meta_desc": False,
        "broken_links": []
    }

    try:
        response = requests.get(url, timeout=5)

        time_ms = round(response.elapsed.total_seconds() * 1000)
        results["response_time"] = time_ms

        if time_ms < 200:
            results["speed_rating"] = "Excellent 🚀"
        elif time_ms < 500:
            results["speed_rating"] = "Good ⚡"
        elif time_ms < 1000:
            results["speed_rating"] = "Average 🐢"
        else:
            results["speed_rating"] = "Slow 🐌"

        if response.url.startswith("https://"):
            results["https"] = True

        if 'Strict-Transport-Security' in response.headers:
            results["hsts"] = True

        if 'X-Frame-Options' in response.headers:
            results["clickjacking"] = True

        if 'X-Content-Type-Options' in response.headers:
            results["mime_sniffing"] = True

        if 'Server' in response.headers:
            results["server_hidden"] = False

        if response.cookies:
            secure_count = 0
            for cookie in response.cookies:
                if cookie.secure:
                    secure_count += 1
            results["cookies_secure"] = f"{secure_count} of {len(response.cookies)} cookies are Secure"
            if secure_count == len(response.cookies):
                results["cookies_score"] = 1
        else:
            results["cookies_secure"] = "No cookies (Safe)"
            results["cookies_score"] = 1

        soup = BeautifulSoup(response.content, 'html.parser')

        meta_desc = soup.find('meta', attrs={'name': 'description'})
        if meta_desc and meta_desc.get('content'):
            results["has_meta_desc"] = True

        images = soup.find_all('img')
        for img in images[:5]:
            src = img.get('src')
            if src and src.startswith('http'):
                try:
                    res = requests.head(src, timeout=2)
                    if res.status_code >= 400:
                        results["broken_links"].append(src)
                except:
                    results["broken_links"].append(src)

        score = 0
        if results["https"]: score += 20
        if results["hsts"]: score += 20
        if results["clickjacking"]: score += 10
        if results["mime_sniffing"]: score += 10
        if results["server_hidden"]: score += 10
        if results["has_meta_desc"]: score += 10
        if results["cookies_score"] == 1: score += 10
        if len(results["broken_links"]) == 0: score += 10
        results["score"] = score

        return results, None

    except Exception as e:
        return None, f"Could not connect: {str(e)}"


@app.route('/', methods=['GET', 'POST'])
def home():
    data = None
    error = None

    if request.method == 'POST':
        url_input = request.form.get('url_input')

        valid_url, validation_error = validate_url(url_input)

        if validation_error:
            error = validation_error
        else:
            data, error = scan_website(valid_url)

    return render_template('index.html', data=data, error=error)


if __name__ == '__main__':
    app.run(debug=True)