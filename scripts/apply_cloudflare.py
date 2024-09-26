import os
import sys
import json
import asyncio
import logging
import yaml
from typing import List, Dict, Union, Any, Optional
from aiohttp import ClientSession
from pydantic import BaseModel, ValidationError, validator
from CloudFlare import CloudFlare, CloudFlareAPIError
from tenacity import retry, stop_after_attempt, wait_exponential
import argparse
import subprocess
from datetime import datetime

# Check if running in a GitHub Actions environment
GITHUB_ACTIONS = os.getenv('GITHUB_ACTIONS') == 'true'

# Configure logging
if GITHUB_ACTIONS:
    logging.basicConfig(level=logging.INFO, format='::%(levelname)s :: %(message)s')
else:
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

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

    @validator("tls_min_version")
    def validate_tls_min_version(cls, value):
        if value not in {"1.0", "1.1", "1.2", "1.3"}:
            raise ValueError("❌ Invalid TLS version. Must be one of '1.0', '1.1', '1.2', '1.3'.")
        return value

    @validator("polish_mode")
    def validate_polish_mode(cls, value):
        if value not in {"off", "lossless", "lossy"}:
            raise ValueError("❌ Invalid Polish mode. Must be 'off', 'lossless', or 'lossy'.")
        return value

class Config(BaseModel):
    cloudflare: Dict[str, Any]

# Retry with exponential backoff for API errors
@retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=4, max=10))
async def apply_settings_for_zone(cf: CloudFlare, zone_id: str, domain: str, settings: CloudflareSettings) -> Dict[str, Any]:
    logging.info(f"Applying settings for domain {domain}...")

    updated_settings = {}
    async with ClientSession() as session:
        settings_dict = settings.dict(exclude_none=True)  # Exclude None values
        try:
            response = await cf.zones.settings.async_patch(zone_id, data=settings_dict)
            updated_settings.update(response)
            logging.info(f"Successfully updated settings for {domain}.")
        except CloudFlareAPIError as e:
            logging.error(f"Failed to update settings for {domain}: {e}")
            raise e  # Retry using tenacity

    return updated_settings

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

def commit_and_push_changes(file_path: str):
    try:
        subprocess.run(['git', 'add', file_path], check=True)
        subprocess.run(['git', 'diff', '--exit-code'], check=True)  # Ensure there are changes
        subprocess.run(['git', 'commit', '-m', 'Updated Cloudflare settings'], check=True)
        subprocess.run(['git', 'push'], check=True)
        logging.info("Changes committed and pushed successfully.")
    except subprocess.CalledProcessError as e:
        logging.error(f"No changes to commit: {e}")

async def main(config_path: str):
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

    cf_token = os.getenv('CLOUDFLARE_API_TOKEN')
    if not cf_token:
        logging.error("Cloudflare API token not found in environment variables.")
        sys.exit(1)

    zone_id = os.getenv('CLOUDFLARE_ZONE_ID')
    if not zone_id:
        logging.error("Cloudflare Zone ID not found in environment variables.")
        sys.exit(1)

    fqdn = os.getenv('CLOUDFLARE_FQDN')
    if not fqdn:
        logging.error("Cloudflare FQDN not found in environment variables.")
        sys.exit(1)

    cf = CloudFlare(token=cf_token)

    for zone in config.cloudflare.get('zones', []):
        domain = fqdn
        settings = CloudflareSettings(**zone.get('settings', {}))

        logging.info(f"Processing zone {zone_id} for domain {domain}...")

        new_config = await apply_settings_for_zone(cf, zone_id, domain, settings)
        json_file_path = save_config_to_json(zone_id, new_config)
        commit_and_push_changes(json_file_path)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Apply Cloudflare settings from a configuration file.")
    parser.add_argument('--config', type=str, required=True, help="Path to the configuration YAML file.")
    args = parser.parse_args()

    asyncio.run(main(args.config))
