"""
This plugin searches for Zigbee and Z-Wave network keys.
"""

import re

from detect_secrets.plugins.base import RegexBasedDetector


class ZigbeeDetector(RegexBasedDetector):
    """Scans for Zigbee and Z-Wave keys."""

    @property
    def secret_type(self) -> str:
        return "Zigbee/Z-Wave Key"

    @property
    def denylist(self) -> list[re.Pattern]:
        return [
            # Zigbee/Z-Wave network/link keys (typically 16-32 hex chars)
            re.compile(
                r"(?i)(zigbee|z.wave)\W*(network|link|trust)\W*key\s*([:='\"]?|is|to)\s*[a-fA-F0-9:]{20,}"
            ),
        ]
