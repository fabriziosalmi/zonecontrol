import os
import sys
import json
import asyncio
import logging
from typing import List, Dict, Union, Any
from aiohttp import ClientSession
from CloudFlare import CloudFlare, CloudFlareAPIError
from tenacity import retry, stop_after_attempt, wait_exponential

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def get_env_variable(var_name: str, default: Any = None, required: bool = False) -> str:
    """
    Helper function to get environment variable with validation
    """
    value = os.getenv(var_name, default)
    if required and not value:
        logging.error(f"Environment variable '{var_name}' is required but not set.")
        sys.exit(1)
    return value

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

async def fetch_paginated_data(cf: CloudFlare, endpoint: str, params: Dict = None) -> List[Dict]:
    """
    Handle paginated data from Cloudflare API
    """
    page = 1
    results = []
    
    while True:
        try:
            response = await asyncio.to_thread(cf.__getattr__(endpoint).get, params={**params, "page": page})
            if 'result' in response:
                results.extend(response['result'])
                if response['result_info']['page'] >= response['result_info']['total_pages']:
                    break
                page += 1
            else:
                break
        except CloudFlareAPIError as e:
            logging.error(f"Error fetching paginated data from endpoint {endpoint}: {e}")
            raise

    return results

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

async def apply_cache_settings(cf: CloudFlare, zone_id: str, cache_level: str, browser_cache_ttl: int) -> None:
    """
    Apply caching settings
    """
    try:
        await asyncio.to_thread(cf.zones.settings.patch, zone_id, data={
            "items": [
                {"id": "cache_level", "value": cache_level},
                {"id": "browser_cache_ttl", "value": browser_cache_ttl}
            ]
        })
        logging.info(f"Cache settings applied: Cache Level = {cache_level}, Browser Cache TTL = {browser_cache_ttl}")
    except CloudFlareAPIError as e:
        logging.error(f"Error applying cache settings: {e}")
        raise

async def apply_image_optimization(cf: CloudFlare, zone_id: str, polish_mode: str) -> None:
    """
    Apply image optimization settings
    """
    try:
        await asyncio.to_thread(cf.zones.settings.patch, zone_id, data={
            "items": [
                {"id": "polish", "value": polish_mode}
            ]
        })
        logging.info(f"Image optimization (Polish) mode set to {polish_mode}")
    except CloudFlareAPIError as e:
        logging.error(f"Error applying image optimization settings: {e}")
        raise

async def main():
    # Load environment variables
    cf_token = get_env_variable('CLOUDFLARE_API_TOKEN', required=True)
    zone_id = get_env_variable('CLOUDFLARE_ZONE_ID', required=True)
    domain = get_env_variable('DOMAIN', required=True)
    enable_http3 = get_env_variable('ENABLE_HTTP3', 'false').lower() == 'true'
    enable_hsts = get_env_variable('ENABLE_HSTS', 'false').lower() == 'true'
    hsts_max_age = int(get_env_variable('HSTS_MAX_AGE', '0'))
    tls_min_version = get_env_variable('TLS_MIN_VERSION', '1.2')
    secure_ciphers = get_env_variable('SECURE_CIPHERS')
    enable_ddos_protection = get_env_variable('ENABLE_DDOS_PROTECTION', 'false').lower() == 'true'
    enable_waf = get_env_variable('ENABLE_WAF', 'false').lower() == 'true'
    enable_dnssec = get_env_variable('ENABLE_DNSSEC', 'false').lower() == 'true'
    enable_https_rewrites = get_env_variable('ENABLE_HTTPS_REWRITES', 'false').lower() == 'true'
    geo_blocking_enabled = get_env_variable('GEO_BLOCKING_ENABLED', 'false').lower() == 'true'
    geo_blocking_countries = get_env_variable('GEO_BLOCKING_COUNTRIES', '').split(',')
    custom_header_enabled = get_env_variable('CUSTOM_HEADER_ENABLED', 'false').lower() == 'true'
    custom_header_key = get_env_variable('CUSTOM_HEADER_KEY')
    custom_header_value = get_env_variable('CUSTOM_HEADER_VALUE')
    cache_level = get_env_variable('CACHE_LEVEL', 'aggressive')
    browser_cache_ttl = int(get_env_variable('BROWSER_CACHE_TTL', '14400'))
    polish_mode = get_env_variable('POLISH_MODE', 'lossless')

    # Initialize Cloudflare client
    cf = CloudFlare(token=cf_token)

    # List of tasks for asynchronous execution
    tasks = []

    # Apply settings
    if enable_http3:
        tasks.append(apply_cloudflare_setting(cf, zone_id, 'http3', 'on', "HTTP/3"))

    if enable_hsts:
        tasks.append(apply_cloudflare_setting(cf, zone_id, 'security_header', {
            "strict_transport_security": {
                "enabled": True,
                "max_age": hsts_max_age,
                "include_subdomains": True,
                "preload": True
            }
        }, "HSTS"))

    tasks.append(apply_cloudflare_setting(cf, zone_id, 'min_tls_version', tls_min_version, "TLS minimum version"))
    
    if secure_ciphers:
        tasks.append(apply_cloudflare_setting(cf, zone_id, 'ciphers', secure_ciphers.split(","), "Secure ciphers"))

    if enable_ddos_protection:
        tasks.append(apply_cloudflare_setting(cf, zone_id, 'ddos_protection', 'on', "DDoS protection"))

    if enable_waf:
        tasks.append(apply_cloudflare_setting(cf, zone_id, 'waf', 'on', "Web Application Firewall"))

    if enable_dnssec:
        tasks.append(apply_cloudflare_setting(cf, zone_id, 'dnssec', 'active', "DNSSEC"))

    if enable_https_rewrites:
        tasks.append(apply_cloudflare_setting(cf, zone_id, 'automatic_https_rewrites', 'on', "Automatic HTTPS Rewrites"))

    if geo_blocking_enabled:
        for country in geo_blocking_countries:
            if country:
                tasks.append(apply_firewall_rule(cf, zone_id, {
                    "action": "block",
                    "filter": {"expression": f"ip.geoip.country eq \"{country}\""},
                    "description": f"Block traffic from {country}"
                }))

    # Apply Firewall rules
    firewall_rules_env = get_env_variable('FIREWALL_RULES', '[]')
    try:
        firewall_rules = json.loads(firewall_rules_env)
        if isinstance(firewall_rules, list):
            tasks.append(apply_firewall_rules(cf, zone_id, firewall_rules))
        else:
            logging.error("FIREWALL_RULES should be a list")
            sys.exit(1)
    except json.JSONDecodeError as e:
        logging.error(f"Error decoding FIREWALL_RULES: {e}")
        sys.exit(1)

    # Apply Custom Header if enabled
    if custom_header_enabled:
        tasks.append(apply_custom_header(cf, zone_id, domain, custom_header_key, custom_header_value))

    # Define Rate Limiting Rule
    rate_limit_rule = {
        "threshold": 1000,
        "period": 60,
        "action": {
            "mode": "simulate",
            "timeout": 60,
            "response": {
                "content_type": "text/plain",
                "body": "This request has been rate-limited."
            }
        },
        "match": {
            "request": {"methods": ["GET"]},
            "response": {"origin_traffic": True},
            "url": "*"
        },
        "enabled": True,
        "description": "Rate limit rule to limit to 1000 requests per minute for GET requests"
    }
    tasks.append(apply_rate_limit(cf, zone_id, rate_limit_rule))

    # Apply Cache Settings
    tasks.append(apply_cache_settings(cf, zone_id, cache_level, browser_cache_ttl))

    # Apply Image Optimization Settings
    tasks.append(apply_image_optimization(cf, zone_id, polish_mode))

    # Run all tasks concurrently
    await asyncio.gather(*tasks)

if __name__ == "__main__":
    asyncio.run(main())
