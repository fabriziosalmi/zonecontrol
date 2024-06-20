#!/bin/bash

set -e  # Exit immediately if a command exits with a non-zero status.

# Variables from environment
CLOUDFLARE_API_TOKEN=$CLOUDFLARE_API_TOKEN
CLOUDFLARE_ACCOUNT_ID=$CLOUDFLARE_ACCOUNT_ID
CLOUDFLARE_ZONE_ID=$CLOUDFLARE_ZONE_ID
DOMAIN=$DOMAIN
DNS_RECORD_TYPE=$DNS_RECORD_TYPE
DNS_RECORD_VALUE=$DNS_RECORD_VALUE

# Headers for API requests
HEADERS="-H \"Authorization: Bearer $CLOUDFLARE_API_TOKEN\" -H \"Content-Type: application/json\""

# Function to apply Cloudflare settings
apply_setting() {
    local ENDPOINT=$1
    local DATA=$2
    local SUCCESS_MESSAGE=$3

    RESPONSE=$(curl -s -X PATCH "$ENDPOINT" $HEADERS --data "$DATA")
    if [[ $(echo "$RESPONSE" | jq -r '.success') == "true" ]]; then
        echo "$SUCCESS_MESSAGE"
    else
        echo "Error applying $SUCCESS_MESSAGE: $RESPONSE" >&2
        exit 1
    fi
}

# Apply security settings
API_URL="https://api.cloudflare.com/client/v4/zones/${CLOUDFLARE_ZONE_ID}/settings"

# HTTP/3
if [[ "${ENABLE_HTTP3}" == "true" ]]; then
    apply_setting "$API_URL" '{"http3":{"value":true}}' "HTTP/3 enabled."
fi

# HSTS
if [[ "${ENABLE_HSTS}" == "true" ]]; then
    apply_setting "$API_URL/security_header" \
      '{"strict_transport_security": {"enabled": true, "max_age": '${HSTS_MAX_AGE}', "include_subdomains": true, "preload": true}}' \
      "HSTS enabled."
fi

# TLS minimum version
apply_setting "$API_URL" '{"min_tls_version":{"value":"'"${TLS_MIN_VERSION}"'"},"tls_1_2_only":{"value":true}}' \
    "TLS minimum version set to ${TLS_MIN_VERSION}."

# Secure ciphers
apply_setting "$API_URL" '{"cipher_suite":{"value":"'"${SECURE_CIPHERS}"'"},"cipher_suites_legacy":{"value":false}}' \
    "Secure ciphers applied."

# DDoS protection
if [[ "${ENABLE_DDOS_PROTECTION}" == "true" ]]; then
    apply_setting "$API_URL" '{"ddos_protection":{"value":"true"}}' "DDoS protection enabled."
fi

# WAF
if [[ "${ENABLE_WAF}" == "true" ]]; then
    apply_setting "$API_URL" '{"web_application_firewall":{"value":"true"}}' "Web Application Firewall enabled."
fi

# DNSSEC
if [[ "${ENABLE_DNSSEC}" == "true" ]]; then
    apply_setting "https://api.cloudflare.com/client/v4/zones/${CLOUDFLARE_ZONE_ID}/dnssec" \
      '{"status":"active"}' "DNSSEC enabled."
fi

# HTTPS rewrites
if [[ "${ENABLE_HTTPS_REWRITES}" == "true" ]]; then
    apply_setting "$API_URL" '{"automatic_https_rewrites":{"value":true}}' "Automatic HTTPS Rewrites enabled."
fi

# Geo-Blocking
if [[ "${GEO_BLOCKING_ENABLED}" == "true" ]]; then
    echo "Configuring Geo-Blocking..."
    IFS=',' read -ra COUNTRIES <<< "${GEO_BLOCKING_COUNTRIES}"
    for COUNTRY in "${COUNTRIES[@]}"; do
        curl -X POST "https://api.cloudflare.com/client/v4/zones/${CLOUDFLARE_ZONE_ID}/firewall/rules" \
          $HEADERS --data '{
            "action": "block",
            "filter": {
              "expression": "ip.geoip.country eq \"'$COUNTRY'\"",
              "description": "Block traffic from '$COUNTRY'"
            }
          }'
        echo "Blocking traffic from $COUNTRY."
    done
fi

# Firewall rules
echo "Applying Firewall Rules..."
echo "${FIREWALL_RULES}" | jq -c '.[]' | while read -r RULE; do
    ACTION=$(echo $RULE | jq -r '.action')
    EXPRESSION=$(echo $RULE | jq -r '.expression')
    curl -X POST "https://api.cloudflare.com/client/v4/zones/${CLOUDFLARE_ZONE_ID}/firewall/rules" \
      $HEADERS --data '{
        "action": "'"$ACTION"'",
        "filter": {
          "expression": "'"$EXPRESSION"'",
          "description": "'"$ACTION"' traffic matching rule"
        }
      }'
    echo "$ACTION traffic matching rule applied: $EXPRESSION"
done

# Custom header
if [[ "${CUSTOM_HEADER_ENABLED}" == "true" ]]; then
    echo "Setting custom header..."
    curl -X POST "https://api.cloudflare.com/client/v4/zones/${CLOUDFLARE_ZONE_ID}/pagerules" \
      $HEADERS --data '{
        "targets": [
          {
            "target": "url",
            "constraint": {
              "operator": "matches",
              "value": "*.'"${DOMAIN}"'/*"
            }
          }
        ],
        "actions": [
          {
            "id": "set_header",
            "value": {
              "headers": [
                {
                  "name": "'"${CUSTOM_HEADER_KEY}"'",
                  "value": "'"${CUSTOM_HEADER_VALUE}"'"
                }
              ]
            }
          }
        ],
        "priority": 1,
        "status": "active"
      }'
    echo "Custom header set: ${CUSTOM_HEADER_KEY}: ${CUSTOM_HEADER_VALUE}"
fi

# Rate Limiting Rule
echo "Setting up rate limiting rule..."
RATE_LIMIT_URL="https://api.cloudflare.com/client/v4/zones/${CLOUDFLARE_ZONE_ID}/rate_limits"
RATE_LIMIT_RULE=$(cat <<EOF
{
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
    "request": {
      "methods": ["GET"]
    },
    "response": {
      "origin_traffic": true
    },
    "url": "*"
  },
  "enabled": true,
  "description": "Rate limit rule to limit to 1000 requests per minute for GET requests"
}
EOF
)
RESPONSE=$(curl -s -X POST "$RATE_LIMIT_URL" $HEADERS --data "$RATE_LIMIT_RULE")
if [[ $(echo "$RESPONSE" | jq -r '.success') == "true" ]]; then
    echo "Rate limiting rule applied successfully."
else
    echo "Failed to apply rate limiting rule: $(echo "$RESPONSE" | jq -r '.errors[] | .message')" >&2
    exit 1
fi
