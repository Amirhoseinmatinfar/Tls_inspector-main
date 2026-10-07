# TLS Inspector --- Advanced HTTPS/TLS Analysis Tool

[![Python](https://img.shields.io/badge/python-3.8%2B-blue?logo=python)](https://www.python.org/)
[![License:
MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**TLS Inspector** is a lightweight command-line tool for inspecting
HTTPS/TLS configurations of a host (domain or IP).\
Ideal for security enthusiasts, penetration testers, and anyone who
wants a quick, in-depth TLS analysis on Kali Linux or any Linux
distribution.

------------------------------------------------------------------------

## Table of Contents

-   [Features](#features)
-   [Requirements](#requirements)
-   [Installation & Usage](#installation--usage)
-   [Sample Output](#sample-output)
-   [GitHub Deployment](#github-deployment)
-   [License](#license)
-   [Pro Tips](#pro-tips--why-its-cool)

------------------------------------------------------------------------

## Features

-   Detect TLS version (e.g., TLSv1.3)\
-   Show current cipher suite\
-   Read certificate details (Subject, Issuer, Expiration)\
-   Warn about expired or self-signed certificates\
-   Output human-readable reports and machine-friendly JSON for
    automation

------------------------------------------------------------------------

## Requirements

-   Python 3.8+ (Python 3.11 recommended for Kali Linux)\
-   No external dependencies --- fully built with Python's standard
    library

------------------------------------------------------------------------

## Installation & Usage

1.  Ensure Python 3 is installed on your system.\

2.  Make the script executable:

    ``` bash
    chmod +x tls_inspector.py
    ```

3.  Run examples:

    ``` bash
    ./tls_inspector.py example.com
    ./tls_inspector.py example.com --port 443 --json
    ```

------------------------------------------------------------------------

## Sample Output

    TLS Inspector
    Host: example.com:443

    TLS Version: TLSv1.3
    Cipher Suite: TLS_AES_256_GCM_SHA384

    Certificate: Trusted (valid chain)
      Subject: CN=example.com, O=Example Org, C=US
      Issuer:  CN=Let's Encrypt Authority X3, O=Let's Encrypt, C=US
      Not After: 2026-06-01T12:00:00+00:00
      Expires in 180 days

------------------------------------------------------------------------


## License

MIT License --- Free to use for educational purposes. Any misuse
violating local laws is solely the responsibility of the user.

------------------------------------------------------------------------

## Pro Tips --- Why It's Cool

-   Fully offline, lightweight, and fast\
-   Works on any Linux distribution without installing dependencies\
-   Outputs JSON for automated scripts, making it perfect for
    pen-testing pipelines\
-   Minimalist but powerful --- just one script, total control
