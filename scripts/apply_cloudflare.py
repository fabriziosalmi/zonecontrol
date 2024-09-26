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
    ssl: Optional[str] = "full"
    min_tls_version: Optional[str] = "1.2"
    http3: Optional[bool] = True

    rocket_loader: Optional[str] = "off"
    brotli: Optional[str] = "on"
    ipv6: Optional[str] = "on"
    always_online: Optional[str] = "on"
    automatic_https_rewrites: Optional[str] = "on"
    opportunistic_encryption: Optional[str] = "on"

    cache_level: Optional[str] = "aggressive"
    browser_cache_ttl: Optional[int] = 14400
    edge_cache_ttl: Optional[int] = 31536000
    challenge_ttl: Optional[int] = 3600

    # Validators to ensure settings are valid
    @field_validator("min_tls_version")
    def validate_tls_version(cls, value):
        if value not in {"1.0", "1.1", "1.2", "1.3"}:
            raise ValueError("Invalid TLS version. Choose one of '1.0', '1.1', '1.2', '1.3'.")
        return value

    @field_validator("ssl")
    def validate_ssl_mode(cls, value):
        if value not in {"off", "flexible", "full", "strict"}:
            raise ValueError("Invalid SSL mode. Choose one of 'off', 'flexible', 'full', 'strict'.")
        return value


# Config class to hold all zones
class Config(BaseModel):
    cloudflare: Dict[str, Any]


# Function to merge default settings with zone-specific settings
def merge_default_settings(default_settings: Dict[str, Any], zone_settings: Dict[str, Any]) -> Dict[str, Any]:
    merged_settings = default_settings.copy()  # Start with default settings
    merged_settings.update(zone_settings)  # Override with zone-specific settings
    return merged_settings


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
                # Capture and log detailed error information
                error_message = response.json().get('errors', [])
                logging.error(f"Failed to update {key} for {domain}: {http_err}")
                if error_message:
                    logging.error(f"API Error Details for {key}: {json.dumps(error_message, indent=4)}")
                else:
                    logging.error(f"No detailed error message provided for {key}.")

                if response.status_code == 403:
                    logging.warning(f"403 Forbidden: {key} cannot be updated for {domain}. Skipping this setting.")
                    continue  # Skip this setting if it's forbidden
                if response.status_code == 400:
                    logging.warning(f"400 Bad Request: Invalid data or configuration for {key}. Check Cloudflare docs for {key}.")
                    continue  # Skip this setting if the data is invalid
                updated_settings[key] = {'error': str(http_err)}
            except Exception as e:
                logging.error(f"Unexpected error while updating {key} for {domain}: {e}")
                updated_settings[key] = {'error': str(e)}

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
        subprocess.run(['git', 'config', '--global', 'user.email', 'ci@example.com'], check=True)
        subprocess.run(['git', 'config', '--global', 'user.name', 'CI User'], check=True)
        subprocess.run(['git', 'add', file_path], check=True)
        subprocess.run(['git', 'diff', '--exit-code'], check=True)  # Ensure there are changes
        subprocess.run(['git', 'commit', '-m', 'Updated Cloudflare settings'], check=True)
        subprocess.run(['git', 'push'], check=True)
        logging.info("Changes committed and pushed successfully.")
    except subprocess.CalledProcessError as e:
        logging.error(f"No changes to commit: {e}")


# Main function to handle all domains
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

    # Get default settings
    default_settings = config.cloudflare.get('default', {})

    # Loop through each domain/zone and apply the settings
    for zone in config.cloudflare.get('zones', []):
        zone_id = zone.get('id')
        fqdn = zone.get('domain')
        zone_settings = zone.get('settings', {})
        
        if not zone_id or not fqdn:
            logging.error(f"Zone ID or domain not found for one of the zones.")
            continue

        # Merge default and zone-specific settings
        merged_settings = merge_default_settings(default_settings, zone_settings)
        settings = CloudflareSettings(**merged_settings)

        logging.info(f"Processing zone {zone_id} for domain {fqdn}...")

        new_config = apply_settings_for_zone(api_token, zone_id, fqdn, settings)
        json_file_path = save_config_to_json(zone_id, new_config)
        commit_and_push_changes(json_file_path)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Apply Cloudflare settings from a configuration file.")
    parser.add_argument('--config', type=str, required=True, help="Path to the configuration YAML file.")
    args = parser.parse_args()

    main(args.config)
