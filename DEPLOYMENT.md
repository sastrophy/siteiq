# SiteIQ - Deployment Guide

Complete setup and deployment instructions for SiteIQ - Website Intelligence Platform.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Quick Start](#quick-start)
- [Development Setup](#development-setup)
- [Production Deployment](#production-deployment)
- [Docker Deployment](#docker-deployment)
- [Configuration](#configuration)
- [Troubleshooting](#troubleshooting)

---

## Prerequisites

### System Requirements

| Requirement | Minimum | Recommended |
|-------------|---------|-------------|
| Python | 3.10+ | 3.12+ |
| RAM | 512 MB | 2 GB |
| Disk Space | 100 MB | 500 MB |
| OS | macOS, Linux, Windows | macOS, Linux |

### Software Dependencies

- Python 3.10 or higher
- pip (Python package manager)
- Git (optional, for cloning)

---

## Quick Start

### 1. Clone or Download

```bash
# If using git
git clone <repository-url>
cd siteiq

# Or navigate to existing directory
cd /path/to/siteiq
```

### 2. Create Virtual Environment

```bash
# Create virtual environment
python3 -m venv venv

# Activate it
# On macOS/Linux:
source venv/bin/activate

# On Windows:
venv\Scripts\activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

### 4. Run the Web Application

```bash
python3 webapp/app.py
```

### 5. Access the Application

Open your browser and navigate to:
```
http://localhost:5000
```

---

## Development Setup

### Directory Structure

```
siteiq/
├── config.py                 # Configuration management
├── conftest.py               # Pytest fixtures
├── requirements.txt          # Python dependencies
├── README.md                 # Project overview
├── DEPLOYMENT.md             # This file
├── venv/                     # Virtual environment (created)
├── payloads/                 # Attack payloads
│   ├── __init__.py
│   ├── sql_injection.py
│   ├── xss.py
│   ├── directory_traversal.py
│   └── wordpress.py
├── utils/                    # Utility modules
│   ├── __init__.py
│   └── scanner.py
├── tests/                    # Test modules
│   ├── __init__.py
│   ├── test_sql_injection.py
│   ├── test_xss.py
│   ├── test_security_headers.py
│   ├── test_ssl_tls.py
│   ├── test_authentication.py
│   ├── test_wordpress.py
│   ├── test_directory_traversal.py
│   └── test_csrf_owasp.py
├── webapp/                   # Web application
│   ├── app.py
│   └── templates/
│       ├── index.html
│       ├── results.html
│       └── help.html
└── reports/                  # Generated reports (auto-created)
```

### Running Tests via CLI

```bash
# Activate virtual environment
source venv/bin/activate

# Run all tests
python3 -m pytest --target-url=https://example.com

# Run specific test category
python3 -m pytest --target-url=https://example.com -m sql_injection

# Run with HTML report
python3 -m pytest --target-url=https://example.com --html=report.html

# Run in parallel (faster)
python3 -m pytest --target-url=https://example.com -n 4
```

### Development Server

```bash
# Run Flask in debug mode (auto-reload on code changes)
cd webapp
FLASK_DEBUG=1 python3 app.py
```

---

## Production Deployment

### Option 1: Gunicorn (Recommended for Linux)

```bash
# Install Gunicorn
pip install gunicorn

# Run with Gunicorn
cd /path/to/siteiq
gunicorn --chdir webapp --bind 0.0.0.0:8000 --workers 4 --threads 2 app:app
```

### Option 2: Waitress (Cross-platform)

```bash
# Install Waitress
pip install waitress

# Run with Waitress
cd /path/to/siteiq/webapp
python3 -c "from waitress import serve; from app import app; serve(app, host='0.0.0.0', port=8000)"
```

### Option 3: Systemd Service (Linux)

Create `/etc/systemd/system/siteiq.service`:

```ini
[Unit]
Description=SiteIQ - Website Intelligence Platform
After=network.target

[Service]
Type=simple
User=www-data
Group=www-data
WorkingDirectory=/path/to/siteiq
Environment="PATH=/path/to/siteiq/venv/bin"
ExecStart=/path/to/siteiq/venv/bin/gunicorn --chdir webapp --bind 127.0.0.1:8000 --workers 4 app:app
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

Enable and start:

```bash
sudo systemctl daemon-reload
sudo systemctl enable siteiq
sudo systemctl start siteiq
sudo systemctl status siteiq
```

### Nginx Reverse Proxy

```nginx
server {
    listen 80;
    server_name siteiq.example.com;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # SSE support (for live console output)
        proxy_set_header Connection '';
        proxy_buffering off;
        proxy_cache off;
        chunked_transfer_encoding off;
    }
}
```

---

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `SITEIQ_TARGET_URL` | Default target URL | (none) |
| `WORDPRESS_PATH` | WordPress installation path | `/blog` |
| `TEST_INTENSITY` | Test intensity level | `medium` |
| `REQUEST_TIMEOUT` | HTTP request timeout (seconds) | `10` |
| `REQUEST_DELAY` | Delay between requests (seconds) | `0.5` |
| `MAX_PAYLOADS` | Max payloads per endpoint | `50` |
| `REPORT_DIR` | Report output directory | `reports` |

### Example Environment File

Create `.env` file:

```bash
SITEIQ_TARGET_URL=https://example.com
WORDPRESS_PATH=/blog
TEST_INTENSITY=medium
REQUEST_DELAY=0.3
```

Load with:
```bash
export $(cat .env | xargs)
```

---

## Security Considerations

### Important Warnings

1. **Authorization Required:** Only test websites you own or have written permission to test.

2. **Network Impact:** Security scans generate significant traffic. Use `--intensity=light` for initial tests.

3. **Legal Compliance:** Unauthorized security testing may violate laws. Ensure compliance with local regulations.

4. **Sensitive Data:** Reports may contain sensitive information. Secure the `reports/` directory.

### Recommended Practices

- Run behind a firewall or VPN
- Restrict access to the web interface (use authentication)
- Regularly clean old reports
- Monitor system resources during scans

---

## Support

For issues and feature requests, please open an issue on the project repository.
