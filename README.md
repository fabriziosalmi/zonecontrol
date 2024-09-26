# Flared

This repository contains a Python script to automate the configuration of Cloudflare settings for one or more zones. The script applies security and performance settings, updates configurations, and tracks changes by saving them to JSON files and pushing them back to the repository.

## Table of Contents

- [Features](#features)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Configuration](#configuration)
  - [YAML Configuration File](#yaml-configuration-file)
- [Usage](#usage)
- [Suggested Default Settings](#suggested-default-settings)
- [Running in GitHub Actions](#running-in-github-actions)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)
- [License](#license)

## Features

- Automates applying Cloudflare settings (e.g., HTTP/3, HSTS, TLS, WAF, DNSSEC).
- Supports multiple zones and configurations via a YAML file.
- Provides detailed logging with emojis for clear communication.
- Saves configuration changes to JSON files.
- Automatically commits and pushes changes to the repository.
- Compatible with GitHub Actions for CI/CD workflows.

## Prerequisites

- Python 3.7 or higher
- Cloudflare account with API token
- Git installed and configured with access to the repository

## Installation

1. **Clone the Repository**

   ```bash
   git clone https://github.com/yourusername/cloudflare-automation.git
   cd cloudflare-automation
   ```

2. **Create a Virtual Environment**

   ```bash
   python -m venv venv
   source venv/bin/activate   # On Windows use `venv\Scripts\activate`
   ```

3. **Install Required Dependencies**

   ```bash
   pip install -r requirements.txt
   ```

   Ensure the `requirements.txt` contains the necessary packages:
   ```text
   aiohttp
   pydantic
   cloudflare
   tenacity
   pyyaml
   ```

## Configuration

### YAML Configuration File

The script relies on a YAML configuration file to define the Cloudflare settings for each zone. Below is an example configuration (`cloudflare.yaml`):

```yaml
cloudflare:
  api_token: "your_cloudflare_api_token"
  zones:
    - id: "zone_id_1"
      domain: "example.com"
      settings:
        enable_http3: true
        enable_hsts: true
        hsts_max_age: 31536000
        tls_min_version: "1.2"
        secure_ciphers: "ECDHE-ECDSA-AES128-GCM-SHA256,ECDHE-RSA-AES128-GCM-SHA256"
        enable_ddos_protection: true
        enable_waf: true
        enable_dnssec: true
        enable_https_rewrites: true
        geo_blocking_enabled: false
        geo_blocking_countries: []
        custom_header_enabled: false
        custom_header_key: ""
        custom_header_value: ""
        cache_level: "Standard"
        browser_cache_ttl: 14400
        polish_mode: "lossless"
        rate_limit:
          threshold: 1000
          period: 60
          action: "simulate"
          timeout: 60
          content_type: "text/plain"
          body: "This request has been rate-limited."
        firewall_rules: []
```

#### Explanation of Settings

- **`api_token`**: Your Cloudflare API token with sufficient permissions to manage settings.
- **`zones`**: A list of zones with their `id`, `domain`, and desired `settings`.
  - **`id`**: Cloudflare Zone ID (found in the Cloudflare dashboard).
  - **`domain`**: The domain name for the Cloudflare zone.
  - **`settings`**: Cloudflare settings to be applied (see [Suggested Default Settings](#suggested-default-settings) below).

## Usage

1. **Run the Script**

   Use the command line to execute the script, providing the path to your YAML configuration file:

   ```bash
   python scripts/cloudflare.py --config conf/cloudflare.yaml
   ```

2. **Observe Output**

   The script will output progress logs, including the application of each setting, any errors encountered, and confirmation of saved configurations.

## Suggested Default Settings

These defaults balance security, performance, and usability. Adjust as necessary:

- **HTTP/3**: `true` - Enables faster and more efficient network connections.
- **HSTS**: `true` - Forces HTTPS connections to improve security.
- **HSTS Max Age**: `31536000` - Enforces HTTPS for one year.
- **TLS Minimum Version**: `"1.2"` - Ensures secure connections.
- **Secure Ciphers**: `"ECDHE-ECDSA-AES128-GCM-SHA256,ECDHE-RSA-AES128-GCM-SHA256"` - Strong encryption.
- **DDoS Protection**: `true` - Protects against DDoS attacks.
- **WAF**: `true` - Web Application Firewall to prevent common attacks.
- **DNSSEC**: `true` - Secures DNS queries.
- **HTTPS Rewrites**: `true` - Ensures all content is served over HTTPS.
- **Geo-Blocking**: `false` - Disable unless specific requirements exist.
- **Custom Headers**: `false` - Disable unless needed for security or compliance.
- **Cache Level**: `"Standard"` - Balance between performance and freshness.
- **Browser Cache TTL**: `14400` - 4 hours.
- **Polish Mode**: `"lossless"` - Optimizes images without quality loss.
- **Rate Limit**: `{ "threshold": 1000, "period": 60, "action": "simulate", "timeout": 60 }` - Basic rate limiting in simulation mode.

## Running in GitHub Actions

To automate the script execution in GitHub Actions, create a workflow file in your repository at `.github/workflows/cloudflare.yml`:

```yaml
name: Cloudflare Automation

on:
  workflow_dispatch:  # Allows manual triggering from the GitHub Actions UI
  schedule:
    - cron: '0 0 * * *'  # Runs daily at midnight

jobs:
  apply-settings:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout repository
        uses: actions/checkout@v2

      - name: Set up Python
        uses: actions/setup-python@v2
        with:
          python-version: '3.9'

      - name: Install dependencies
        run: |
          python -m pip install --upgrade pip
          pip install aiohttp pydantic cloudflare tenacity pyyaml

      - name: Run Cloudflare script
        run: python scripts/cloudflare.py --config conf/cloudflare.yaml
```

## Troubleshooting

- **Invalid API Token**: Ensure your API token has the necessary permissions for the zones you are managing.
- **Configuration Errors**: Verify that the YAML file is correctly formatted and all required fields are filled.
- **Git Errors**: Make sure your Git configuration allows committing and pushing changes from the environment where the script is running.

## Contributing

Contributions are welcome! Please fork the repository and submit a pull request with your improvements.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.


### Additional Notes

- **YAML Configuration File**: The structure of the YAML file allows for easy customization of settings per domain. Ensure the correct Cloudflare zone IDs and domains are specified.
- **Running in CI/CD Pipelines**: By integrating the script into GitHub Actions, you can automate the execution and track changes in the repository.
- **Extensible and Customizable**: The script can be extended to handle more settings or use cases by modifying the Python script or YAML configuration file.
