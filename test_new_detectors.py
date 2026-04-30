import sys
import os
import re

# Add llm-guard to path
sys.path.append(os.getcwd())

from llm_guard.input_scanners.secrets_plugins.mqtt import MQTTDetector
from llm_guard.input_scanners.secrets_plugins.zigbee import ZigbeeDetector
from llm_guard.input_scanners.secrets_plugins.tuya import TuyaSmartDetector

def test_detector(detector_class, test_cases):
    detector = detector_class()
    print(f"--- Testing {detector_class.__name__} ---")
    for test_case in test_cases:
        found = False
        for pattern in detector.denylist:
            if pattern.search(test_case):
                found = True
                break
        result = "PASSED (Found Secret)" if found else "FAILED (No Secret Found)"
        print(f"Input: {test_case}\nResult: {result}\n")

mqtt_cases = [
    "Connect to mqtt://admin:password123@broker.hivemq.com:1883",
    "Set the mqtt_username to 'iot_user' and mqtt_password to 'supersecret'",
    "The MQTT key is ABCD-1234-EFGH",
]

zigbee_cases = [
    "The Zigbee network key is 01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF",
    "z-wave trust key: 5A:6B:7C:8D:9E:0F:1A:2B:3C:4D:5E:6F:7A:8B:9C:0D",
]

tuya_cases = [
    "Tuya Client ID: v8u9n6x4h5y2p1z7q0w3",
    "tuya_client_secret = 9e8d7c6b5a4f3e2d1c0b9a8f7e6d5c4b",
]

if __name__ == "__main__":
    test_detector(MQTTDetector, mqtt_cases)
    test_detector(ZigbeeDetector, zigbee_cases)
    test_detector(TuyaSmartDetector, tuya_cases)
