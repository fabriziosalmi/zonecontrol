import os
import sys
import json
import logging
import yaml
import requests
from typing import List, Dict, Union, Any, Optional
from pydantic import BaseModel, ValidationError, field_validator
from tenacity import retry, stop_after_attempt, wait_exponential
import argparse
import subprocess

# Check if running in a GitHub Actions environment
GITHUB_ACTIONS = os.getenv('GITHUB_ACTIONS') == 'true'

# Configure logging
if GITHUB_ACTIONS:
    logging.basicConfig(level=logging.INFO, format='::%(levelname)s :: %(message)s')
else:
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


# Cloudflare settings validation using Pydantic
class CloudflareSettings(BaseModel):
    enable_http3: Optional[bool] = False
    enable_hsts: Optional[bool] = False
    hsts_max_age: Optional[int] = 0
    tls_min_version: str = "1.2"
    secure_ciphers: Optional[str] = ""
    enable_ddos_protection: Optional[bool] = False
    enable_waf: Optional[bool] = False
    enable_dnssec: Optional[bool] = False
    enable_https_rewrites: Optional[bool] = False
    geo_blocking_enabled: Optional[bool] = False
    geo_blocking_countries: List[str] = []
    custom_header_enabled: Optional[bool] = False
    custom_header_key: Optional[str] = ""
    custom_header_value: Optional[str] = ""
    cache_level: Optional[str] = "aggressive"
    browser_cache_ttl: Optional[int] = 14400
    polish_mode: Optional[str] = "off"
    rate_limit: Optional[Dict[str, Union[int, str]]] = {}
    firewall_rules: Optional[List[Dict[str, str]]] = []

    @field_validator("tls_min_version")
    def validate_tls_min_version(cls, value):
        if value not in {"1.0", "1.1", "1.2", "1.3"}:
            raise ValueError("❌ Invalid TLS version. Must be one of '1.0', '1.1', '1.2', '1.3'.")
        return value

    @field_validator("polish_mode")
    def validate_polish_mode(cls, value):
        if value not in {"off", "lossless", "lossy"}:
            raise ValueError("❌ Invalid Polish mode. Must be 'off', 'lossless', or 'lossy'.")
        return value


# Root config class
class Config(BaseModel):
    cloudflare: Dict[str, Any]


# Function to validate the API token by calling the Cloudflare API
def validate_api_token(api_token: str) -> bool:
    url = "https://api.cloudflare.com/client/v4/user/tokens/verify"
    headers = {
        'Authorization': f'Bearer {api_token}',
        'Content-Type': 'application/json'
    }

    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()  # Will raise HTTPError for 4xx/5xx status codes
        logging.info("Cloudflare API token is valid.")
        return True
    except requests.RequestException as e:
        logging.error(f"API token validation failed: {e}")
        return False


# Retry with exponential backoff for API errors
@retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=4, max=10))
def apply_settings_for_zone(api_token: str, zone_id: str, domain: str, settings: CloudflareSettings) -> Dict[str, Any]:
    logging.info(f"Applying settings for domain {domain}...")

    headers = {
        'Authorization': f'Bearer {api_token}',
        'Content-Type': 'application/json'
    }

    base_url = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/settings"
    settings_dict = settings.dict(exclude_none=True)  # Exclude None values
    updated_settings = {}

    for key, value in settings_dict.items():
        if value is not None:
            logging.info(f"Updating {key} to {value} for {domain}...")
            try:
                response = requests.patch(f"{base_url}/{key}", headers=headers, json={"value": value})
                response.raise_for_status()
                updated_settings[key] = response.json()
                logging.info(f"Successfully updated {key} to {value} for {domain}.")
            except requests.HTTPError as http_err:
                if response.status_code == 403:
                    logging.error(f"Forbidden (403): Failed to update {key} for {domain}. Aborting operation.")
                    sys.exit(1)  # Exit the script if forbidden errors occur
                logging.error(f"Failed to update {key} for {domain}: {http_err}")
                updated_settings[key] = {'error': str(http_err)}
    return updated_settings


# Function to save the updated config as JSON
def save_config_to_json(zone_id: str, config: Dict[str, Any]) -> str:
    json_path = f"output/{zone_id}_config.json"
    try:
        os.makedirs('output', exist_ok=True)  # Create output directory if it doesn't exist
        with open(json_path, 'w') as f:
            json.dump(config, f, indent=4)
        logging.info(f"Configuration saved to {json_path}")
    except Exception as e:
        logging.error(f"Failed to save configuration to JSON: {e}")
    return json_path


# Function to commit and push changes to the repository
def commit_and_push_changes(file_path: str):
    try:
        subprocess.run(['git', 'add', file_path], check=True)
        subprocess.run(['git', 'diff', '--exit-code'], check=True)  # Ensure there are changes
        subprocess.run(['git', 'commit', '-m', 'Updated Cloudflare settings'], check=True)
        subprocess.run(['git', 'push'], check=True)
        logging.info("Changes committed and pushed successfully.")
    except subprocess.CalledProcessError as e:
        logging.error(f"No changes to commit: {e}")


# Main function
def main(config_path: str):
    try:
        with open(config_path, 'r') as file:
            config_data = yaml.safe_load(file)
    except Exception as e:
        logging.error(f"Failed to read configuration file: {e}")
        sys.exit(1)

    try:
        config = Config.parse_obj(config_data)
    except ValidationError as e:
        logging.error(f"Invalid configuration file: {e}")
        sys.exit(1)

    api_token = os.getenv('CLOUDFLARE_API_TOKEN')
    if not api_token:
        logging.error("Cloudflare API token not found in environment variables.")
        sys.exit(1)

    # Validate the API token before proceeding
    if not validate_api_token(api_token):
        logging.error("API token validation failed. Exiting.")
        sys.exit(1)

    zone_id = os.getenv('CLOUDFLARE_ZONE_ID')
    if not zone_id:
        logging.error("Cloudflare Zone ID not found in environment variables.")
        sys.exit(1)

    fqdn = os.getenv('CLOUDFLARE_FQDN')
    if not fqdn:
        logging.error("Cloudflare FQDN not found in environment variables.")
        sys.exit(1)

    for zone in config.cloudflare.get('zones', []):
        domain = fqdn
        settings = CloudflareSettings(**zone.get('settings', {}))

        logging.info(f"Processing zone {zone_id} for domain {domain}...")

        new_config = apply_settings_for_zone(api_token, zone_id, domain, settings)
        json_file_path = save_config_to_json(zone_id, new_config)
        commit_and_push_changes(json_file_path)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Apply Cloudflare settings from a configuration file.")
    parser.add_argument('--config', type=str, required=True, help="Path to the configuration YAML file.")
    args = parser.parse_args()

    main(args.config)
