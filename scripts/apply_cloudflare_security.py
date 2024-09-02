import os
import sys
import json
from CloudFlare import CloudFlare, CloudFlareAPIError

def log_error(message, error):
    print(f"{message}: {error}")
    sys.exit(1)

def get_env_variable(var_name, default=None, required=False):
    value = os.getenv(var_name, default)
    if required and not value:
        log_error(f"Environment variable '{var_name}' is required but not set", "")
    return value

def apply_cloudflare_setting(cf, zone_id, setting_id, setting_value, setting_description):
    try:
        cf.zones.settings.patch(zone_id, data={"items": [{"id": setting_id, "value": setting_value}]})
        print(f"{setting_description} applied.")
    except CloudFlareAPIError as e:
        log_error(f"Error applying {setting_description}", e)

def apply_firewall_rules(cf, zone_id, rules):
    for rule in rules:
        try:
            cf.zones.firewall.rules.post(zone_id, data={
                "action": rule['action'],
                "filter": {"expression": rule['expression']},
                "description": f"{rule['action']} traffic matching rule"
            })
            print(f"{rule['action']} rule applied: {rule['expression']}")
        except CloudFlareAPIError as e:
            log_error(f"Error applying firewall rule: {rule}", e)

def main():
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

    # Initialize Cloudflare client
    cf = CloudFlare(token=cf_token)

    # Apply settings
    if enable_http3:
        apply_cloudflare_setting(cf, zone_id, 'http3', 'on', "HTTP/3")

    if enable_hsts:
        try:
            cf.zones.settings.patch(zone_id, data={
                "items": [{
                    "id": "security_header",
                    "value": {
                        "strict_transport_security": {
                            "enabled": True,
                            "max_age": hsts_max_age,
                            "include_subdomains": True,
                            "preload": True
                        }
                    }
                }]
            })
            print("HSTS enabled.")
        except CloudFlareAPIError as e:
            log_error("Error enabling HSTS", e)

    apply_cloudflare_setting(cf, zone_id, 'min_tls_version', tls_min_version, "TLS minimum version")
    
    if secure_ciphers:
        apply_cloudflare_setting(cf, zone_id, 'ciphers', secure_ciphers.split(","), "Secure ciphers")

    if enable_ddos_protection:
        apply_cloudflare_setting(cf, zone_id, 'ddos_protection', 'on', "DDoS protection")

    if enable_waf:
        apply_cloudflare_setting(cf, zone_id, 'waf', 'on', "Web Application Firewall")

    if enable_dnssec:
        try:
            cf.zones.dnssec.patch(zone_id, data={"status": "active"})
            print("DNSSEC enabled.")
        except CloudFlareAPIError as e:
            log_error("Error enabling DNSSEC", e)

    if enable_https_rewrites:
        apply_cloudflare_setting(cf, zone_id, 'automatic_https_rewrites', 'on', "Automatic HTTPS Rewrites")

    if geo_blocking_enabled:
        for country in geo_blocking_countries:
            if country:
                try:
                    cf.zones.firewall.rules.post(zone_id, data={
                        "action": "block",
                        "filter": {"expression": f"ip.geoip.country eq \"{country}\""},
                        "description": f"Block traffic from {country}"
                    })
                    print(f"Blocking traffic from {country}.")
                except CloudFlareAPIError as e:
                    log_error(f"Error blocking traffic from {country}", e)

    # Apply Firewall rules
    firewall_rules_env = get_env_variable('FIREWALL_RULES', '[]')
    try:
        firewall_rules = json.loads(firewall_rules_env)
        if isinstance(firewall_rules, list):
            apply_firewall_rules(cf, zone_id, firewall_rules)
        else:
            log_error("FIREWALL_RULES should be a list", "")
    except json.JSONDecodeError as e:
        log_error("Error decoding FIREWALL_RULES", e)

    if custom_header_enabled:
        try:
            cf.zones.pagerules.post(zone_id, data={
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
            print(f"Custom header set: {custom_header_key}: {custom_header_value}")
        except CloudFlareAPIError as e:
            log_error("Error setting custom header", e)

    # Apply Rate Limiting Rule
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
    try:
        response = cf.zones.rate_limits.post(zone_id, data=rate_limit_rule)
        if response.get('success', False):
            print("Rate limiting rule applied successfully.")
        else:
            print(f"Failed to apply rate limiting rule: {response}")
            sys.exit(1)
    except CloudFlareAPIError as e:
        log_error("Error applying rate limiting rule", e)

if __name__ == "__main__":
    main()
