# 🌐 Flared (Cloudflare Zones Settings Automation)

Welcome to **Flared** (Cloudflare Zones Settings Automation), a powerful, scalable, and fully automated solution for managing and applying your Cloudflare zone configurations across multiple domains. This tool allows you to define default configurations and customize settings for individual domains, all while leveraging Cloudflare’s robust API for performance, security, and caching management.

## 🚀 Project Summary

This project provides an **automated and centralized solution** to manage multiple Cloudflare domains (zones) using a **single YAML configuration file**. By defining your zone configurations in a declarative manner, you can easily apply settings such as SSL/TLS configurations, HTTP/3, caching rules, and performance optimizations across all your domains with a simple script.

### Key Features:
- **Multi-domain support** for scalable zone management.
- **Declarative YAML configuration** for easy adjustments.
- **CI/CD automation** with GitHub Actions or other pipelines.
- **Free plan compatibility** with Cloudflare’s most essential settings.

## ✨ Features Overview

### Core Features
- **Multi-Domain Support**: Manage multiple Cloudflare zones/domains from a single configuration file.
- **Default Configurations**: Define default settings that apply to all zones, with the ability to override them for specific domains.
- **Customization**: Tailor settings like SSL/TLS versions, HTTP/3, Rocket Loader, Brotli compression, caching, and more.
- **Free Plan Compatible**: Out-of-the-box support for Cloudflare's free plan settings.

### Automation and Security
- **API Token Security**: Securely handle Cloudflare API tokens via GitHub Secrets.
- **Automation**: Integrate with GitHub Actions or CI/CD tools for recurring updates.
- **Error Handling & Logging**: Comprehensive logging and robust error handling, ensuring unsupported configurations are skipped without breaking the workflow.
- **Version Control**: Automatically push updates to your repository for easy configuration tracking.

## 🛠️ How It Works

### 1. **Configuration**
Define all zone settings in a YAML file. Common configurations are placed under a `default` section, while customizations are made on a per-zone basis.

### 2. **Execution**
The script reads the configuration, applies settings using Cloudflare’s API, and commits any configuration updates back to your repository.

### 3. **Automation**
This setup works seamlessly with GitHub Actions (or any CI/CD tool) to automate the configuration process on a schedule or trigger.

## 📄 YAML Configuration Example

The configuration is written in YAML format for simplicity. Below is an example that defines default settings and customizations for specific domains.

```yaml
cloudflare:
  default:
    # Default settings that apply to all zones unless overridden
    ssl: "full"
    min_tls_version: "1.2"
    http3: true
    rocket_loader: "off"
    brotli: "on"
    ipv6: "on"
    always_online: "on"
    automatic_https_rewrites: "on"
    opportunistic_encryption: "on"
    cache_level: "aggressive"
    browser_cache_ttl: 14400
    edge_cache_ttl: 31536000
    challenge_ttl: 3600

  zones:
    - id: "1234567890abcdef1234567890abcdef"
      domain: "example.com"
      # This zone inherits all settings from default except those explicitly defined here
      settings:
        ssl: "strict"
        min_tls_version: "1.3"  # Override the default for this zone

    - id: "0987654321fedcba0987654321fedcba"
      domain: "anotherdomain.com"
      # This zone can inherit settings from default without overriding anything
      settings: {}
```

### Key Sections:
- **`default`**: Common settings that apply to all domains unless overridden.
- **`zones`**: List of individual zones (domains), each of which can inherit from or override the default settings.
- **Zone IDs and FQDNs are hardcoded**: The Zone IDs (`id`) and domains (`domain`) are explicitly specified in the YAML file.

## 🏗️ Setup Instructions

### 1. Prerequisites
- **Cloudflare Account**: Ensure you have an active Cloudflare account and API token with appropriate permissions.
- **GitHub Repository**: Prepare a GitHub repository containing your YAML configuration file and script.
- **GitHub Actions Setup**: This solution is designed to work seamlessly with GitHub Actions, but can also be adapted for any CI/CD tool.

### 2. Installation
```bash
git clone https://github.com/fabriziosalmi/flared.git
cd flared
```

### 3. Configuration
- **Cloudflare API Token**: Create your API token via the [Cloudflare dashboard](https://dash.cloudflare.com/profile/api-tokens) and add it to GitHub Secrets as `CLOUDFLARE_API_TOKEN`.
- **YAML Configuration**: Edit `config/cloudflare.yaml` to define your zone settings, hardcoding the Zone IDs and domain names.

### 4. Running the Script
```bash
python scripts/apply_cloudflare.py --config config/cloudflare.yaml
```

### 5. Automating with GitHub Actions
Create the following workflow file to automate updates:
```yaml
name: Cloudflare Settings Automation

on:
  workflow_dispatch:
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
          python -m venv venv
          source venv/bin/activate
          python -m pip install --upgrade pip
          pip install requests pydantic tenacity pyyaml

      - name: Run Cloudflare script
        env:
          CLOUDFLARE_API_TOKEN: ${{ secrets.CLOUDFLARE_API_TOKEN }}
        run: |
          source venv/bin/activate
          python scripts/apply_cloudflare.py --config config/cloudflare.yaml

      - name: Handle errors
        if: failure()
        run: echo "::error::Workflow failed at some steps."
```

## 📊 Example Output

Here’s an example log output showing a successful update:
```
::INFO :: Cloudflare API token is valid.
::INFO :: Processing zone example.com...
::INFO :: Successfully updated SSL to full for example.com.
::INFO :: Successfully updated HTTP/3 for example.com.
...
::INFO :: Configuration saved to output/example_com_config.json
```

## 🛡️ Security Considerations

### Token and Secret Management
- **API Token**: Never store your Cloudflare API token in the repository. Use environment variables or GitHub Secrets to protect sensitive information.
- **Hardcoded Zone IDs**: Ensure the Zone IDs and domains in the YAML configuration remain up to date.

### Error Handling
The script handles errors gracefully, skipping invalid or unsupported configurations, ensuring your workflow isn’t disrupted.

## 🔧 Customization and Extensibility

This project is highly customizable. Add support for new Cloudflare features, integrate with other CI/CD systems, or modify the YAML structure to suit your specific use case.

## 👨‍💻 Contributing

Contributions are welcome! If you have new feature suggestions or find bugs, feel free to open an issue or submit a pull request.

## 📄 License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for more details.
