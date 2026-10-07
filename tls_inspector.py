
#!/usr/bin/env python3
\"\"\"TLS Inspector - simple CLI tool to inspect TLS/HTTPS details for a host.
Features:
 - TLS protocol version (e.g. TLSv1.3)
 - Cipher suite in use
 - Certificate details (subject, issuer, notAfter)
 - Certificate expiration and basic trust check
 - JSON or human-readable terminal output
Usage examples:
  ./tls_inspector.py example.com
  ./tls_inspector.py example.com --port 443 --json
  ./tls_inspector.py 1.1.1.1 --port 443
Notes:
 - Designed to be safe, educational and runnable on Kali/Linux (Python 3.8+).
 - Does not perform any intrusive scanning; it only opens a TLS handshake to the target host/port.
\"\"\"

import argparse
import socket
import ssl
import sys
from datetime import datetime, timezone
import json

ANSI = {
    'red': '\\033[31m',
    'green': '\\033[32m',
    'yellow': '\\033[33m',
    'blue': '\\033[34m',
    'bold': '\\033[1m',
    'reset': '\\033[0m'
}

def color(text, col):
    return f\"{ANSI.get(col,'')}\" + str(text) + ANSI['reset']

def readable_name(item):
    # item from cert subject/issuer: a tuple of tuples
    parts = []
    for tup in item:
        for k,v in tup:
            parts.append(f\"{k}={v}\")
    return \", \".join(parts)

def inspect_host(host, port=443, timeout=6):
    result = {
        'host': host,
        'port': port,
        'connected': False,
        'trusted': None,
        'error': None,
        'tls_version': None,
        'cipher': None,
        'certificate': None
    }

    # First try a verifying context (uses system CA store)
    try:
        context = ssl.create_default_context()
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                result['connected'] = True
                result['trusted'] = True
                result['tls_version'] = ssock.version()
                cipher = ssock.cipher()
                result['cipher'] = cipher[0] if cipher else None
                cert = ssock.getpeercert()
                result['certificate'] = cert
                return result
    except Exception as e:
        # Save the error but continue to try to fetch certificate in unverified mode
        result['error'] = str(e)

    # If verifying failed (e.g., self-signed, expired, untrusted CA), try an unverified context to still read cert
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                result['connected'] = True
                # trusted remains False because first attempt failed
                result['trusted'] = False if result['trusted'] is None else result['trusted']
                result['tls_version'] = ssock.version()
                cipher = ssock.cipher()
                result['cipher'] = cipher[0] if cipher else None
                cert = ssock.getpeercert()
                result['certificate'] = cert
                return result
    except Exception as e:
        # final failure
        result['error'] = result.get('error') + ' || ' + str(e) if result.get('error') else str(e)
        return result

def analyze_certificate(cert):
    # cert is the dict returned by SSLSocket.getpeercert()
    if not cert:
        return None
    analysis = {}
    # Subject
    subj = cert.get('subject', ())
    iss = cert.get('issuer', ())
    analysis['subject'] = readable_name(subj)
    analysis['issuer'] = readable_name(iss)
    notAfter = cert.get('notAfter')
    if notAfter:
        try:
            # ssl.cert_time_to_seconds is available in Python 3.8+
            seconds = ssl.cert_time_to_seconds(notAfter)
            exp = datetime.fromtimestamp(seconds, tz=timezone.utc)
            now = datetime.now(tz=timezone.utc)
            analysis['notAfter'] = exp.isoformat()
            analysis['days_to_expiry'] = (exp - now).days
            analysis['expired'] = (exp < now)
        except Exception:
            analysis['notAfter'] = notAfter
    # Sanity checks
    analysis['self_signed'] = (analysis.get('subject') == analysis.get('issuer'))
    return analysis

def pretty_print(res):
    if not res['connected']:
        print(color('✖ Could not connect', 'red'), f\"to {res['host']}:{res['port']}\")
        if res.get('error'):
            print(color('Error:', 'yellow'), res['error'])
        return

    print(color('TLS Inspector', 'bold'))
    print(f\"Host: {res['host']}:{res['port']}\")
    print('')

    print(color('TLS Version:', 'blue'), res.get('tls_version') or 'N/A')
    print(color('Cipher Suite:', 'blue'), res.get('cipher') or 'N/A')
    print('')

    cert = res.get('certificate')
    if not cert:
        print(color('No certificate information available', 'yellow'))
        return
    analysis = analyze_certificate(cert)
    trusted = res.get('trusted')
    trust_text = 'Trusted (valid chain)' if trusted else 'Untrusted / could not verify'
    trust_col = 'green' if trusted else 'yellow'
    print(color('Certificate:', 'bold'), color(trust_text, trust_col))
    print('  Subject:', analysis.get('subject'))
    print('  Issuer: ', analysis.get('issuer'))
    print('  Not After:', analysis.get('notAfter'))
    days = analysis.get('days_to_expiry')
    if days is not None:
        if analysis.get('expired'):
            print(color(f'  Status: EXPIRED ({days} days past)', 'red'))
        else:
            print(color(f'  Expires in {days} days', 'green' if days>30 else 'yellow'))
    if analysis.get('self_signed'):
        print(color('  NOTE: Certificate appears self-signed (subject == issuer).', 'yellow'))

def main():
    parser = argparse.ArgumentParser(description='TLS Inspector - inspect TLS/HTTPS details for a host.')
    parser.add_argument('host', help='Hostname or IP to inspect (e.g. example.com)')
    parser.add_argument('--port', '-p', type=int, default=443, help='TCP port (default: 443)')
    parser.add_argument('--timeout', '-t', type=float, default=6.0, help='Connection timeout in seconds')
    parser.add_argument('--json', action='store_true', help='Output JSON machine-readable results')
    args = parser.parse_args()

    res = inspect_host(args.host, port=args.port, timeout=args.timeout)
    if args.json:
        # augment certificate analysis
        out = dict(res)
        out['certificate_analysis'] = analyze_certificate(res.get('certificate')) if res.get('certificate') else None
        print(json.dumps(out, indent=2, default=str))
        return

    pretty_print(res)

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print('\\nInterrupted by user.')
        sys.exit(2)
