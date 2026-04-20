"""
This plugin searches for Tuya IoT access keys (Client ID and Secret)
"""

import re

from detect_secrets.plugins.base import RegexBasedDetector


class TuyaSmartDetector(RegexBasedDetector):
    """Scans for Tuya IoT access keys."""

    @property
    def secret_type(self) -> str:
        return "Tuya IoT Access Key"

    @property
    def denylist(self) -> list[re.Pattern]:
        return [
            # Tuya Client ID (20 characters, alphanumeric)
            re.compile(
                r"""(?i)tuya.*client.*id.*[:=].*([a-z0-9]{20})"""
            ),
            # Tuya Client Secret (32 characters, alphanumeric)
            re.compile(
                r"""(?i)tuya.*client.*secret.*[:=].*([a-z0-9]{32})"""
            ),
        ]
