import pytest
from apply_cloudflare import (
    CloudflareSettings, Config, merge_default_settings, validate_api_token,
    apply_settings_for_zone, save_config_to_json, commit_and_push_changes, main
)
from unittest.mock import patch, MagicMock

# Test CloudflareSettings validation
def test_cloudflare_settings_validation():
    settings = CloudflareSettings(ssl="full", min_tls_version="1.2")
    assert settings.ssl == "full"
    assert settings.min_tls_version == "1.2"

def test_cloudflare_settings_validation_error():
    with pytest.raises(ValidationError):
        CloudflareSettings(ssl="invalid", min_tls_version="1.3")

# Test merge_default_settings
def test_merge_default_settings():
    default = {"a": 1, "b": 2}
    zone = {"b": 3, "c": 4}
    merged = merge_default_settings(default, zone)
    assert merged == {"a": 1, "b": 3, "c": 4}

# Test validate_api_token
@patch('requests.get')
def test_validate_api_token(mock_get):
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_get.return_value = mock_response
    assert validate_api_token("token") is True

@patch('requests.get')
def test_validate_api_token_error(mock_get):
    mock_response = MagicMock()
    mock_response.status_code = 401
    mock_get.return_value = mock_response
    assert validate_api_token("token") is False

# Test apply_settings_for_zone
@patch('apply_cloudflare.requests.patch')
def test_apply_settings_for_zone(mock_patch):
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_patch.return_value = mock_response
    settings = CloudflareSettings(ssl="full")
    result = apply_settings_for_zone("token", "zone_id", "domain", settings)
    assert result == {'ssl': {'success': True}}

@patch('apply_cloudflare.requests.patch')
def test_apply_settings_for_zone_error(mock_patch):
    mock_response = MagicMock()
    mock_response.status_code = 403
    mock_patch.return_value = mock_response
    settings = CloudflareSettings(ssl="full")
    result = apply_settings_for_zone("token", "zone_id", "domain", settings)
    assert result == {'ssl': {'error': '403 Forbidden: ssl cannot be updated for domain. Skipping this setting.'}}

# Test save_config_to_json
@patch('apply_cloudflare.os.makedirs')
@patch('apply_cloudflare.json.dump')
def test_save_config_to_json(mock_dump, mock_makedirs):
    save_config_to_json("zone_id", {"a": 1})

# Test commit_and_push_changes
@patch('apply_cloudflare.subprocess.run')
def test_commit_and_push_changes(mock_run):
    commit_and_push_changes("file_path")

# Test main
@patch('apply_cloudflare.main')
def test_main(mock_main):
    with patch('argparse.ArgumentParser.parse_args', return_value=MagicMock(config='config.yaml')):
        main()
    mock_main.assert_called_once_with('config.yaml')