import io
import re
import dns.resolver
import smtplib
import socket
import random
import string
import requests
import pandas as pd
import concurrent.futures
import time
from flask import Flask, request, render_template, make_response

app = Flask(__name__)

# --------- ORIGINAL HELPERS (unaltered logic) ---------

# Fetch full list of disposable domains from GitHub
def fetch_disposable_domains():
    url = "https://raw.githubusercontent.com/disposable-email-domains/disposable-email-domains/master/disposable_email_blocklist.conf"
    try:
        response = requests.get(url)
        response.raise_for_status()
        domains = {line.strip().lower() for line in response.text.splitlines() if line.strip() and not line.startswith('#')}
        return domains
    except Exception as e:
        print(f"Failed to fetch disposable domains: {e}")
        return set()

DISPOSABLE_DOMAINS = fetch_disposable_domains()

# Common role-based usernames (expanded)
ROLE_BASED_USERNAMES = {
    "admin", "administrator", "info", "support", "sales", "contact",
    "webmaster", "no-reply", "noreply", "abuse", "postmaster", "help",
    "billing", "marketing", "team", "office", "hello", "root", "hostmaster",
    "sysadmin", "feedback", "privacy", "security", "jobs", "career", "press",
    "media", "inquiries", "legal", "compliance", "hr", "accounts"
}

def is_valid_email_format(email):
    pattern = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
    return re.match(pattern, email) is not None

def get_mx_records(domain, retries=3):
    for attempt in range(retries):
        try:
            records = dns.resolver.resolve(domain, 'MX')
            return sorted([(int(r.preference), str(r.exchange).rstrip('.')) for r in records])
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.Timeout, dns.exception.DNSException):
            if attempt < retries - 1:
                time.sleep(1)  # Delay before retry
            else:
                return []

def is_mail_server_reachable(mx_host, retries=3):
    for attempt in range(retries):
        try:
            ip = socket.gethostbyname(mx_host)
            with socket.create_connection((ip, 25), timeout=20):
                return True
        except (socket.gaierror, socket.timeout, OSError):
            if attempt < retries - 1:
                time.sleep(1)
            else:
                return False

def check_smtp_response(email, mx_records, from_email='test@yourdomain.com', retries=3):
    for attempt in range(retries):
        for priority, mx_host in mx_records:
            try:
                server = smtplib.SMTP(mx_host, 25, timeout=30)
                server.ehlo_or_helo_if_needed()
                server.mail(from_email)
                code, message = server.rcpt(email)
                server.quit()
                return code, message.decode() if isinstance(message, bytes) else message
            except (smtplib.SMTPException, OSError) as e:
                continue
        if attempt < retries - 1:
            time.sleep(1)
    return None, "Could not connect to any MX server after retries"

def is_catch_all(domain, mx_records):
    fake_user = ''.join(random.choices(string.ascii_lowercase + string.digits, k=30))
    fake_email = f"{fake_user}@{domain}"
    code, msg = check_smtp_response(fake_email, mx_records)
    return code == 250 if code else False

def is_disposable_domain(domain):
    return domain.lower() in DISPOSABLE_DOMAINS

def is_role_based(email):
    username = email.split('@')[0].lower()
    return any(username.startswith(role) or username == role for role in ROLE_BASED_USERNAMES)

# --------- FLASK ROUTE (does the same processing) ---------

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        if 'file' not in request.files:
            return render_template('index.html', error="No file uploaded")
        file = request.files['file']
        if file.filename == '' or not file.filename.lower().endswith('.csv'):
            return render_template('index.html', error="Invalid file (must be CSV)")

        try:
            df = pd.read_csv(file)
        except Exception as e:
            return render_template('index.html', error=f"Failed to read CSV: {e}")

        print(f"Loaded {len(DISPOSABLE_DOMAINS)} disposable domains.")

        # Detect email column
        email_col = None
        for col in df.columns:
            if "email" in col.lower():
                email_col = col
                break

        if email_col is None:
            max_matches = 0
            for col in df.columns:
                matches = sum(
                    1 for val in df[col].head(10)
                    if isinstance(val, str) and re.match(r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$', val)
                )
                if matches > max_matches:
                    max_matches = matches
                    email_col = col

        if email_col is None:
            return render_template('index.html', error="No email column detected")

        print(f"Detected email column: '{email_col}'")

        df['Validation_Status'] = ''
        df['domain'] = ''  # Temporary column

        print("Starting fast checks...")
        # Fast checks (serial, as they are quick)
        for idx, email in enumerate(df[email_col]):
            print(f"Fast check for email {idx + 1}: {email}")
            if pd.isna(email) or not isinstance(email, str):
                df.at[idx, 'Validation_Status'] = "Invalid - Not a string"
                continue
            if not is_valid_email_format(email):
                df.at[idx, 'Validation_Status'] = "Invalid - Invalid format"
                continue
            try:
                username, domain = email.lower().split('@')
            except ValueError:
                df.at[idx, 'Validation_Status'] = "Invalid - Invalid format"
                continue
            if is_disposable_domain(domain):
                df.at[idx, 'Validation_Status'] = "Invalid - Disposable domain detected"
                continue
            if is_role_based(email):
                df.at[idx, 'Validation_Status'] = "Invalid - Role-based address detected (potential spam trap)"
                continue
            df.at[idx, 'domain'] = domain
        print("Fast checks completed.")

        # Emails needing further checks
        to_check = df[df['Validation_Status'] == '']

        if not to_check.empty:
            unique_domains = to_check['domain'].unique()
            print(f"Starting parallel domain checks for {len(unique_domains)} unique domains...")

            # Parallel domain checks
            def domain_check(domain):
                print(f"Checking domain: {domain}")
                time.sleep(0.2)  # Throttle to avoid rate limits
                mx = get_mx_records(domain)
                if not mx:
                    return domain, {'mx': [], 'reachable': False, 'catch_all': False}
                pref_mx = mx[0][1]
                reachable = is_mail_server_reachable(pref_mx)
                catch_all = is_catch_all(domain, mx) if reachable else False
                return domain, {'mx': mx, 'reachable': reachable, 'catch_all': catch_all}

            with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
                results = list(executor.map(domain_check, unique_domains))
            domain_cache = dict(results)
            print("Domain checks completed.")

            # Apply domain results
            print("Applying domain results...")
            for idx in to_check.index:
                domain = df.at[idx, 'domain']
                cache = domain_cache[domain]
                if not cache['mx']:
                    df.at[idx, 'Validation_Status'] = "Invalid - No MX records (domain invalid or no mail server)"
                    continue
                if not cache['reachable']:
                    df.at[idx, 'Validation_Status'] = "Invalid - Mail server not reachable"
                    continue
                if cache['catch_all']:
                    df.at[idx, 'Validation_Status'] = "Invalid - Catch-all domain detected (cannot reliably verify mailbox)"
                    continue
            print("Domain results applied.")

            # Emails needing SMTP verify
            to_verify = df[df['Validation_Status'] == '']

            if not to_verify.empty:
                print(f"Starting parallel SMTP verification for {len(to_verify)} emails...")

                # Parallel verify
                def verify_single(args):
                    email, domain = args
                    print(f"Verifying email: {email}")
                    time.sleep(0.2)  # Throttle
                    mx = domain_cache[domain]['mx']
                    code, msg = check_smtp_response(email, mx)
                    if code == 250:
                        return "Valid"
                    elif code:
                        return f"Invalid - Server rejected: {msg} (code {code})"
                    else:
                        return f"Invalid - {msg}"

                verify_args = [(row[email_col], row['domain']) for idx, row in to_verify.iterrows()]

                with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
                    statuses = list(executor.map(verify_single, verify_args))

                # Set statuses
                for row_idx, status in zip(to_verify.index, statuses):
                    df.at[row_idx, 'Validation_Status'] = status
                print("SMTP verification completed.")

        # Clean up
        df.drop('domain', axis=1, inplace=True)

        # Prepare download
        output = io.StringIO()
        df.to_csv(output, index=False)
        output.seek(0)

        response = make_response(output.getvalue())
        response.headers["Content-Disposition"] = "attachment; filename=verified_test.csv"
        response.headers["Content-type"] = "text/csv"
        return response

    # GET → render upload page
    return render_template('index.html')

if __name__ == '__main__':
    # Run on localhost:5000
    app.run(debug=True, port=5000)
