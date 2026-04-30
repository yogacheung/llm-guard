"""
This plugin searches for MQTT broker credentials and connection strings.
"""

import re

from detect_secrets.plugins.base import RegexBasedDetector


class MQTTDetector(RegexBasedDetector):
    """Scans for MQTT broker credentials."""

    @property
    def secret_type(self) -> str:
        return "MQTT Credentials"

    @property
    def denylist(self) -> list[re.Pattern]:
        return [
            # MQTT connection string with credentials: mqtt://user:pass@host:port
            re.compile(r"mqtts?://[^:]+:[^@]+@"),
            # MQTT user/pass patterns
            re.compile(r"(?i)mqtt[\W_]*(user(name)?|pass(word)?|token|key)\s*([:='\"]|is|to)\s*['\"]?[a-zA-Z0-9_\-\.]{4,}['\"]?"),
        ]
