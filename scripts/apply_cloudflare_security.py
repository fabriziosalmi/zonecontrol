import os
import sys
import json
from CloudFlare import CloudFlare

def main():
    # Environment variables
    cf_token = os.getenv('CLOUDFLARE_API_TOKEN')
    zone_id = os.getenv('CLOUDFLARE_ZONE_ID')
    domain = os.getenv('DOMAIN')
    dns_record_type = os.getenv('DNS_RECORD_TYPE')
    dns_record_value = os.getenv('DNS_RECORD_VALUE')
    enable_http3 = os.getenv('ENABLE_HTTP3', 'false').lower() == 'true'
    enable_hsts = os.getenv('ENABLE_HSTS', 'false').lower() == 'true'
    hsts_max_age = int(os.getenv('HSTS_MAX_AGE', '0'))
    tls_min_version = os.getenv('TLS_MIN_VERSION')
    secure_ciphers = os.getenv('SECURE_CIPHERS')
    enable_ddos_protection = os.getenv('ENABLE_DDOS_PROTECTION', 'false').lower() == 'true'
    enable_waf = os.getenv('ENABLE_WAF', 'false').lower() == 'true'
    enable_dnssec = os.getenv('ENABLE_DNSSEC', 'false').lower() == 'true'
    enable_https_rewrites = os.getenv('ENABLE_HTTPS_REWRITES', 'false').lower() == 'true'
    geo_blocking_enabled = os.getenv('GEO_BLOCKING_ENABLED', 'false').lower() == 'true'
    geo_blocking_countries = os.getenv('GEO_BLOCKING_COUNTRIES', '').split(',')
    custom_header_enabled = os.getenv('CUSTOM_HEADER_ENABLED', 'false').lower() == 'true'
    custom_header_key = os.getenv('CUSTOM_HEADER_KEY')
    custom_header_value = os.getenv('CUSTOM_HEADER_VALUE')

    # Validate and load FIREWALL_RULES
    firewall_rules_env = os.getenv('FIREWALL_RULES', '[]')
    print(f"FIREWALL_RULES environment variable content: {firewall_rules_env}")
    
    try:
        firewall_rules = json.loads(firewall_rules_env)
        if not isinstance(firewall_rules, list):
            raise ValueError("FIREWALL_RULES should be a list.")
    except json.JSONDecodeError as e:
        print(f"Error decoding FIREWALL_RULES: {e}. Defaulting to an empty list.")
        firewall_rules = []
    except ValueError as e:
        print(f"Value error: {e}. Defaulting to an empty list.")
        firewall_rules = []
    
    print(f"Parsed FIREWALL_RULES: {firewall_rules}")

    # Initialize Cloudflare client
    cf = CloudFlare(token=cf_token)

    # Apply HTTP/3 setting
    if enable_http3:
        cf.zones.settings.patch(zone_id, data={"http3": {"value": True}})
        print("HTTP/3 enabled.")

    # Apply HSTS setting
    if enable_hsts:
        cf.zones.settings.patch(zone_id, data={
            "security_header": {
                "strict_transport_security": {
                    "enabled": True,
                    "max_age": hsts_max_age,
                    "include_subdomains": True,
                    "preload": True
                }
            }
        })
        print("HSTS enabled.")

    # Apply TLS minimum version setting
    cf.zones.settings.patch(zone_id, data={
        "min_tls_version": {"value": tls_min_version},
        "tls_1_2_only": {"value": True}
    })
    print(f"TLS minimum version set to {tls_min_version}.")

    # Apply secure ciphers setting
    cf.zones.settings.patch(zone_id, data={
        "ciphers": {"value": secure_ciphers.split(",")}
    })
    print("Secure ciphers applied.")

    # Apply DDoS protection setting
    if enable_ddos_protection:
        cf.zones.settings.patch(zone_id, data={"ddos_protection": {"value": "on"}})
        print("DDoS protection enabled.")

    # Apply WAF setting
    if enable_waf:
        cf.zones.settings.patch(zone_id, data={"waf": {"value": "on"}})
        print("Web Application Firewall enabled.")

    # Apply DNSSEC setting
    if enable_dnssec:
        cf.zones.dnssec.post(zone_id, data={"status": "active"})
        print("DNSSEC enabled.")

    # Apply HTTPS rewrites setting
    if enable_https_rewrites:
        cf.zones.settings.patch(zone_id, data={"automatic_https_rewrites": {"value": True}})
        print("Automatic HTTPS Rewrites enabled.")

    # Apply Geo-Blocking settings
    if geo_blocking_enabled:
        for country in geo_blocking_countries:
            if country:
                cf.zones.firewall.rules.post(zone_id, data={
                    "action": "block",
                    "filter": {"expression": f"ip.geoip.country eq \"{country}\""},
                    "description": f"Block traffic from {country}"
                })
                print(f"Blocking traffic from {country}.")

    # Apply Firewall rules
    for rule in firewall_rules:
        cf.zones.firewall.rules.post(zone_id, data={
            "action": rule['action'],
            "filter": {"expression": rule['expression']},
            "description": f"{rule['action']} traffic matching rule"
        })
        print(f"{rule['action']} traffic matching rule applied: {rule['expression']}")

    # Apply Custom Header settings
    if custom_header_enabled:
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
    response = cf.zones.rate_limits.post(zone_id, data=rate_limit_rule)
    if 'success' in response and response['success']:
        print("Rate limiting rule applied successfully.")
    else:
        print(f"Failed to apply rate limiting rule: {response}")
        sys.exit(1)

if __name__ == "__main__":
    main()
