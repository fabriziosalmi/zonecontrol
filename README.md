# Flared

This repository utilizes a GitHub Actions workflow to manage and apply security settings for a Cloudflare zone, including the creation and configuration of subdomains.

## Workflow Overview

The workflow performs the following steps:
1. Checks if a specified subdomain exists on Cloudflare and creates it if it doesn't.
2. Configures various Cloudflare security settings.
3. Fetches and applies a list of banned IPs from CrowdSec.
4. Applies custom firewall rules and settings.

## Variables and Secrets

To run this workflow, you need to configure several variables and secrets in your GitHub repository settings. Below is a table listing all the required variables and secrets:

### Variables

| Variable Name                | Description                                                              | Example Values               |
|------------------------------|--------------------------------------------------------------------------|-------------------------------|
| `DOMAIN`                     | The subdomain to manage (e.g., `sub.example.com`).                       | `sub.example.com`             |
| `CLOUDFLARE_ZONE_ID`         | The Cloudflare Zone ID for the parent domain.                            | `your_zone_id_here`           |
| `DNS_RECORD_TYPE`            | The type of DNS record to create (`A` or `CNAME`).                       | `A`, `CNAME`                  |
| `DNS_RECORD_VALUE`           | The value for the DNS record (IP for `A` or target domain for `CNAME`).  | `192.0.2.1`, `target.example.com` |
| `ENABLE_HTTP3`               | Enable HTTP/3 (true or false).                                           | `true`                        |
| `ENABLE_HSTS`                | Enable HTTP Strict Transport Security (HSTS) (true or false).            | `true`                        |
| `HSTS_MAX_AGE`               | HSTS max-age in seconds.                                                 | `31536000`                    |
| `TLS_MIN_VERSION`            | Minimum TLS version to support.                                          | `1.2`, `1.3`                  |
| `SECURE_CIPHERS`             | List of secure ciphers to use.                                           | `ECDHE-RSA-AES128-GCM-SHA256` |
| `ENABLE_DDOS_PROTECTION`     | Enable DDoS protection (true or false).                                  | `true`                        |
| `ENABLE_WAF`                 | Enable Web Application Firewall (WAF) (true or false).                   | `true`                        |
| `ENABLE_DNSSEC`              | Enable DNSSEC (true or false).                                           | `true`                        |
| `ENABLE_HTTPS_REWRITES`      | Enable automatic HTTPS rewrites (true or false).                         | `true`                        |
| `ZERO_TRUST_APP_ENABLED`     | Enable Zero Trust Application (true or false).                           | `true`                        |
| `ZERO_TRUST_APP_NAME`        | Name of the Zero Trust Application.                                       | `ZeroTrustApp`                |
| `ZERO_TRUST_APP_DOMAIN`      | Domain for the Zero Trust Application.                                    | `zt.example.com`              |
| `ZERO_TRUST_APP_POLICY_TYPE` | Type of Zero Trust Application access policy (e.g., `ip`, `email`).      | `ip`                          |
| `ZERO_TRUST_APP_POLICY_VALUE`| Value for the Zero Trust Application access policy.                      | `203.0.113.0/24`              |
| `GEO_BLOCKING_ENABLED`       | Enable Geo-blocking (true or false).                                     | `true`                        |
| `GEO_BLOCKING_COUNTRIES`     | Comma-separated list of country codes to block.                          | `CN,RU,IR`                    |
| `FIREWALL_RULES`             | JSON string representing custom firewall rules.                          | JSON-formatted rules          |
| `CUSTOM_HEADER_ENABLED`      | Enable custom headers (true or false).                                   | `true`                        |
| `CUSTOM_HEADER_KEY`          | Custom header key.                                                       | `X-Custom-Header`             |
| `CUSTOM_HEADER_VALUE`        | Custom header value.                                                     | `CustomValue`                 |

### Secrets

| Secret Name               | Description                                       | Example Value               |
|---------------------------|---------------------------------------------------|-----------------------------|
| `CLOUDFLARE_API_TOKEN`    | Your Cloudflare API token.                        | `your_cloudflare_api_token` |
| `CLOUDFLARE_ACCOUNT_ID`   | Your Cloudflare Account ID for Zero Trust apps.   | `your_account_id_here`      |

## Adding Variables and Secrets

To add these variables and secrets:

1. **Navigate to your GitHub repository**:
   - Go to the `Settings` tab.
   - Click on `Secrets and variables` under `Security`.

2. **Add Secrets**:
   - Click `New repository secret` for each secret.
   - Provide the secret name (e.g., `CLOUDFLARE_API_TOKEN`) and its value.

3. **Add Variables**:
   - Click `New repository variable` for each variable.
   - Provide the variable name (e.g., `DOMAIN`) and its value.

## Running the Workflow

Once you have set up all the required variables and secrets, you can manually trigger the workflow or wait for the scheduled run.

To manually trigger the workflow:
1. Go to the `Actions` tab in your GitHub repository.
2. Select the workflow named `Apply Cloudflare Security Settings`.
3. Click the `Run workflow` button and confirm.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
