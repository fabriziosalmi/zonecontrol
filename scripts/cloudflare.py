import os
import sys
import json
import asyncio
import logging
import yaml
from typing import List, Dict, Union, Any
from aiohttp import ClientSession
from pydantic import BaseModel, ValidationError, validator
from CloudFlare import CloudFlare, CloudFlareAPIError
from tenacity import retry, stop_after_attempt, wait_exponential
import argparse
import subprocess
from datetime import datetime

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class CloudflareSettings(BaseModel):
    enable_http3: bool = False
    enable_hsts: bool = False
    hsts_max_age: int = 0
    tls_min_version: str = "1.2"
    secure_ciphers: str = ""
    enable_ddos_protection: bool = False
    enable_waf: bool = False
    enable_dnssec: bool = False
    enable_https_rewrites: bool = False
    geo_blocking_enabled: bool = False
    geo_blocking_countries: List[str] = []
    custom_header_enabled: bool = False
    custom_header_key: str = ""
    custom_header_value: str = ""
    cache_level: str = "aggressive"
    browser_cache_ttl: int = 14400
    polish_mode: str = "off"
    rate_limit: Dict[str, Union[int, str]] = {}
    firewall_rules: List[Dict[str, str]] = []

    @validator("tls_min_version")
    def validate_tls_min_version(cls, value):
        if value not in {"1.0", "1.1", "1.2", "1.3"}:
            raise ValueError("Invalid TLS version. Must be one of '1.0', '1.1', '1.2', '1.3'.")
        return value

    @validator("polish_mode")
    def validate_polish_mode(cls, value):
        if value not in {"off", "lossless", "lossy"}:
            raise ValueError("Invalid Polish mode. Must be 'off', 'lossless', or 'lossy'.")
        return value

class Config(BaseModel):
    cloudflare: Dict[str, Any]

@retry(stop=stop_after_attempt(5), wait=wait_exponential(multiplier=1, min=2, max=10))
async def apply_cloudflare_setting(cf: CloudFlare, zone_id: str, setting_id: str, setting_value: Union[str, Dict], setting_description: str) -> None:
    """
    Apply a specific Cloudflare setting with retries
    """
    try:
        await asyncio.to_thread(cf.zones.settings.patch, zone_id, data={"items": [{"id": setting_id, "value": setting_value}]})
        logging.info(f"{setting_description} applied.")
    except CloudFlareAPIError as e:
        logging.error(f"Error applying {setting_description}: {e}")
        raise

async def fetch_cloudflare_settings(cf: CloudFlare, zone_id: str) -> Dict[str, Any]:
    """
    Fetch the current Cloudflare settings for a given zone
    """
    try:
        settings = await asyncio.to_thread(cf.zones.settings.get, zone_id)
        logging.info("Fetched current Cloudflare settings.")
        return settings
    except CloudFlareAPIError as e:
        logging.error(f"Error fetching Cloudflare settings: {e}")
        raise

async def apply_firewall_rules(cf: CloudFlare, zone_id: str, rules: List[Dict]) -> None:
    """
    Apply firewall rules concurrently
    """
    tasks = [apply_firewall_rule(cf, zone_id, rule) for rule in rules]
    await asyncio.gather(*tasks)

@retry(stop=stop_after_attempt(5), wait=wait_exponential(multiplier=1, min=2, max=10))
async def apply_firewall_rule(cf: CloudFlare, zone_id: str, rule: Dict) -> None:
    """
    Apply a single firewall rule with retries
    """
    try:
        await asyncio.to_thread(cf.zones.firewall.rules.post, zone_id, data=rule)
        logging.info(f"{rule['action']} rule applied: {rule['filter']['expression']}")
    except CloudFlareAPIError as e:
        logging.error(f"Error applying firewall rule: {rule}. Error: {e}")
        raise

async def apply_custom_header(cf: CloudFlare, zone_id: str, domain: str, custom_header_key: str, custom_header_value: str) -> None:
    """
    Apply a custom header via Cloudflare page rules
    """
    try:
        await asyncio.to_thread(cf.zones.pagerules.post, zone_id, data={
            "targets": [{
                "target": "url",
                "constraint": {
                    "operator": "matches",
                    "value": f"*.{domain}/*"
                }
            }],
            "actions": [{
                "id": "set_header",
                "value": {
                    "headers": [{
                        "name": custom_header_key,
                        "value": custom_header_value
                    }]
                }
            }],
            "priority": 1,
            "status": "active"
        })
        logging.info(f"Custom header set: {custom_header_key}: {custom_header_value}")
    except CloudFlareAPIError as e:
        logging.error(f"Error setting custom header: {e}")
        raise

async def apply_rate_limit(cf: CloudFlare, zone_id: str, rate_limit_rule: Dict) -> None:
    """
    Apply a rate limiting rule
    """
    try:
        response = await asyncio.to_thread(cf.zones.rate_limits.post, zone_id, data=rate_limit_rule)
        if response.get('success', False):
            logging.info("Rate limiting rule applied successfully.")
        else:
            logging.error(f"Failed to apply rate limiting rule: {response}")
            sys.exit(1)
    except CloudFlareAPIError as e:
        logging.error(f"Error applying rate limiting rule: {e}")
        raise

async def apply_settings_for_zone(cf: CloudFlare, zone_id: str, domain: str, settings: CloudflareSettings) -> Dict[str, Any]:
    """
    Apply all settings for a given zone
    """
    tasks = []

    if settings.enable_http3:
        tasks.append(apply_cloudflare_setting(cf, zone_id, 'http3', 'on', "HTTP/3"))

    if settings.enable_hsts:
        tasks.append(apply_cloudflare_setting(cf, zone_id, 'security_header', {
            "strict_transport_security": {
                "enabled": True,
                "max_age": settings.hsts_max_age,
                "include_subdomains": True,
                "preload": True
            }
        }, "HSTS"))

    tasks.append(apply_cloudflare_setting(cf, zone_id, 'min_tls_version', settings.tls_min_version, "TLS minimum version"))
    
    if settings.secure_ciphers:
        tasks.append(apply_cloudflare_setting(cf, zone_id, 'ciphers', settings.secure_ciphers.split(","), "Secure ciphers"))

    if settings.enable_ddos_protection:
        tasks.append(apply_cloudflare_setting(cf, zone_id, 'ddos_protection', 'on', "DDoS protection"))

    if settings.enable_waf:
        tasks.append(apply_cloudflare_setting(cf, zone_id, 'waf', 'on', "Web Application Firewall"))

    if settings.enable_dnssec:
        tasks.append(apply_cloudflare_setting(cf, zone_id, 'dnssec', 'active', "DNSSEC"))

    if settings.enable_https_rewrites:
        tasks.append(apply_cloudflare_setting(cf, zone_id, 'automatic_https_rewrites', 'on', "Automatic HTTPS Rewrites"))

    if settings.geo_blocking_enabled:
        for country in settings.geo_blocking_countries:
            if country:
                tasks.append(apply_firewall_rule(cf, zone_id, {
                    "action": "block",
                    "filter": {"expression": f"ip.geoip.country eq \"{country}\""},
                    "description": f"Block traffic from {country}"
                }))

    # Apply Firewall rules
    if settings.firewall_rules:
        tasks.append(apply_firewall_rules(cf, zone_id, settings.firewall_rules))

    # Apply Custom Header if enabled
    if settings.custom_header_enabled:
        tasks.append(apply_custom_header(cf, zone_id, domain, settings.custom_header_key, settings.custom_header_value))

    # Apply Rate Limiting Rule
    if settings.rate_limit:
        rate_limit_rule = {
            "threshold": settings.rate_limit.get("threshold", 1000),
            "period": settings.rate_limit.get("period", 60),
            "action": {
                "mode": settings.rate_limit.get("action", "simulate"),
                "timeout": settings.rate_limit.get("timeout", 60),
                "response": {
                    "content_type": settings.rate_limit.get("content_type", "text/plain"),
                    "body": settings.rate_limit.get("body", "This request has been rate-limited.")
                }
            },
            "match": {
                "request": {"methods": ["GET"]},
                "response": {"origin_traffic": True},
                "url": "*"
            },
            "enabled": True,
            "description": "Rate limit rule to limit requests per configuration"
        }
        tasks.append(apply_rate_limit(cf, zone_id, rate_limit_rule))

    # Apply Cache Settings
    tasks.append(apply_cloudflare_setting(cf, zone_id, 'cache_level', settings.cache_level, "Cache level"))
    tasks.append(apply_cloudflare_setting(cf, zone_id, 'browser_cache_ttl', settings.browser_cache_ttl, "Browser Cache TTL"))

    # Apply Image Optimization Settings
    tasks.append(apply_cloudflare_setting(cf, zone_id, 'polish', settings.polish_mode, "Image Optimization (Polish Mode)"))

    # Run all tasks concurrently
    await asyncio.gather(*tasks)

    # Fetch updated settings
    return await fetch_cloudflare_settings(cf, zone_id)

def save_config_to_json(zone_id: str, new_config: Dict[str, Any]):
    """
    Save the updated Cloudflare configuration to a JSON file
    """
    json_filename = f"conf/{zone_id}_cloudflare_config_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(json_filename, 'w') as json_file:
        json.dump(new_config, json_file, indent=4)
    logging.info(f"Saved updated configuration to {json_filename}.")
    return json_filename

def commit_and_push_changes(file_path: str):
    """
    Commit and push the JSON file with updated Cloudflare settings back to the repository
    """
    try:
        subprocess.run(["git", "add", file_path], check=True)
        subprocess.run(["git", "commit", "-m", "Update Cloudflare configuration settings"], check=True)
        subprocess.run(["git", "push"], check=True)
        logging.info("Changes committed and pushed to the repository.")
    except subprocess.CalledProcessError as e:
        logging.error(f"Failed to commit and push changes: {e}")

async def main(config_path: str):
    # Load configuration from YAML file
    with open(config_path, 'r') as file:
        config_data = yaml.safe_load(file)
    
    try:
        config = Config.parse_obj(config_data)
    except ValidationError as e:
        logging.error(f"Invalid configuration file: {e}")
        sys.exit(1)

    cf_token = config.cloudflare.get('api_token')
    cf = CloudFlare(token=cf_token)

    # Process each zone
    for zone in config.cloudflare.get('zones', []):
        zone_id = zone.get('id')
        domain = zone.get('domain')
        settings = CloudflareSettings(**zone.get('settings', {}))

        # Apply settings and fetch updated configuration
        new_config = await apply_settings_for_zone(cf, zone_id, domain, settings)

        # Save new configuration to JSON
        json_file_path = save_config_to_json(zone_id, new_config)

        # Commit and push the changes
        commit_and_push_changes(json_file_path)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Apply Cloudflare settings from a configuration file.")
    parser.add_argument('--config', type=str, required=True, help="Path to the configuration YAML file.")
    args = parser.parse_args()

    asyncio.run(main(args.config))
