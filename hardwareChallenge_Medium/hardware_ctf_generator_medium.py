import random
import json
import requests
import base64
import hashlib
import os
import zipfile
import tempfile
from faker import Faker

class HardwareCTFGeneratorMedium:
    def __init__(self):
        self.fake = Faker()
        self.categories = [
            "Firmware Analysis",
            "UART Debugging",
            "EEPROM Extraction",
            "JTAG Interface",
            "PCB Reverse Engineering"
        ]
        self.difficulty = "Medium"
        self.value_range = (200, 300)
        self.max_attempts = 5
        self.challenge_types = [
            "Basic UART Access",
            "Simple Firmware Disassembly",
            "EEPROM Dump Analysis",
            "Debug Interface Dump",
            "Signal Monitoring"
        ]

    def generate_random_flag(self):
        prefix = random.choice(["FLAG", "CTF"])
        secret = self.fake.lexify(text='??????????????', letters='abcdef1234567890')
        return f"{prefix}{{{secret}}}"

    def generate_firmware_with_flag(self, flag):
        data = b"BOOT" + b"\x00" * 100 + flag.encode() + b"\xFF" * 100
        return base64.b64encode(data).decode()

    def generate_uart_log(self, flag):
        log = f"Connecting...\nWelcome to debug console\nEnter command: >>>\nAccess granted.\nFLAG: {flag}\n"
        return log.encode()

    def generate_eeprom_dump(self, flag):
        dump = bytearray([random.randint(0, 255) for _ in range(256)])
        insert_pos = random.randint(50, 150)
        dump[insert_pos:insert_pos + len(flag)] = flag.encode()
        return dump

    def generate_challenge(self):
        challenge_type = random.choice(self.challenge_types)
        flag = self.generate_random_flag()

        challenge = {
            "name": f"{challenge_type} Challenge",
            "category": random.choice(self.categories),
            "description": "",
            "value": random.randint(*self.value_range),
            "max_attempts": self.max_attempts,
            "type": "standard",
            "state": "visible",
            "flags": [{"type": "static", "content": flag}],
            "files": [],
            "hints": [],
            "requirements": None
        }

        if "UART" in challenge_type:
            log = self.generate_uart_log(flag)
            encoded = base64.b64encode(log).decode()
            challenge["description"] = (
                "A UART debug interface has been discovered. Analyze the communication log and recover the flag."
            )
            challenge["files"].append({
                "name": "uart_log.txt",
                "content": encoded,
                "type": "text/plain",
                "encoding": "base64"
            })

        elif "Firmware" in challenge_type:
            fw = self.generate_firmware_with_flag(flag)
            challenge["description"] = (
                "A simple firmware was dumped from the flash memory. Try to reverse it and extract the flag."
            )
            challenge["files"].append({
                "name": "firmware_dump.bin",
                "content": fw,
                "type": "application/octet-stream",
                "encoding": "base64"
            })

        elif "EEPROM" in challenge_type:
            dump = self.generate_eeprom_dump(flag)
            encoded = base64.b64encode(dump).decode()
            challenge["description"] = (
                "Analyze this raw EEPROM memory dump and locate the hidden flag."
            )
            challenge["files"].append({
                "name": "eeprom_dump.bin",
                "content": encoded,
                "type": "application/octet-stream",
                "encoding": "base64"
            })

        elif "Debug" in challenge_type:
            challenge["description"] = (
                "We got access to a memory dump through a debug interface. Somewhere in it lies a secret..."
            )
            debug_dump = flag.encode() + b"\x00" * 200
            encoded = base64.b64encode(debug_dump).decode()
            challenge["files"].append({
                "name": "debug_memory.bin",
                "content": encoded,
                "type": "application/octet-stream",
                "encoding": "base64"
            })

        elif "Signal" in challenge_type:
            signal_trace = json.dumps([random.randint(0, 255) for _ in range(300)])
            challenge["description"] = (
                "We captured signal data during an operation. Can you interpret the trace and recover the flag?"
            )
            challenge["files"].append({
                "name": "signal_trace.json",
                "content": signal_trace,
                "type": "application/json"
            })

        # Add a hint (optional)
        if random.random() > 0.5:
            challenge["hints"].append({
                "content": "Try strings or hexdump to begin with.",
                "cost": 75
            })

        return challenge

    def upload_to_ctfd(self, challenge, ctfd_url, api_key):
        headers = {
            "Authorization": f"Token {api_key}",
            "Content-Type": "application/json"
        }

        # Create challenge
        response = requests.post(
            f"{ctfd_url}/api/v1/challenges",
            headers=headers,
            json={
                "name": challenge["name"],
                "category": challenge["category"],
                "description": challenge["description"],
                "value": challenge["value"],
                "type": challenge["type"],
                "state": challenge["state"],
                "max_attempts": challenge["max_attempts"]
            }
        )

        if response.status_code != 200:
            print(f"Error creating challenge: {response.text}")
            return False

        challenge_id = response.json()["data"]["id"]

        # Add flag
        flag_data = {
            "content": challenge["flags"][0]["content"],
            "type": "static",
            "challenge_id": challenge_id
        }

        response = requests.post(f"{ctfd_url}/api/v1/flags", headers=headers, json=flag_data)
        if response.status_code != 200:
            print(f"Error adding flag: {response.text}")

        # Add files
        if challenge["files"]:
            with tempfile.TemporaryDirectory() as tmpdir:
                zip_path = os.path.join(tmpdir, f"{challenge_id}_challenge.zip")
                with zipfile.ZipFile(zip_path, 'w') as zipf:
                    for file in challenge["files"]:
                        file_path = os.path.join(tmpdir, file["name"])
                        content = base64.b64decode(file["content"]) if file.get("encoding") == "base64" else file["content"].encode()
                        with open(file_path, 'wb') as f:
                            f.write(content)
                        zipf.write(file_path, arcname=file["name"])

                files = {
                    'file': (os.path.basename(zip_path), open(zip_path, 'rb')),
                    'challenge_id': (None, str(challenge_id)),
                    'type': (None, 'challenge')
                }

                file_response = requests.post(
                    f"{ctfd_url}/api/v1/files",
                    headers={"Authorization": f"Token {api_key}"},
                    files=files
                )

                if file_response.status_code != 200:
                    print(f"Error uploading file: {file_response.text}")

        # Add hints
        for hint in challenge["hints"]:
            response = requests.post(
                f"{ctfd_url}/api/v1/hints",
                headers=headers,
                json={
                    "challenge_id": challenge_id,
                    "content": hint["content"],
                    "cost": hint["cost"]
                }
            )
            if response.status_code != 200:
                print(f"Error adding hint: {response.text}")

        return True


if __name__ == "__main__":
    generator = HardwareCTFGeneratorMedium()
    challenges = [generator.generate_challenge() for _ in range(5)]

    # Save locally
    with open("hardware_ctf_medium.json", "w") as f:
        json.dump(challenges, f, indent=2)

    print("✅ Generated 5 Medium difficulty Hardware CTF challenges.")

    # Upload to CTFd
    CTFD_URL = "http://13.50.80.30:8000"
    API_KEY = "ctfd_c6d86a975a46d36674bf23584b7d64c9515ca20c5c8a12e690cccad30995eaf9"

    for challenge in challenges:
        result = generator.upload_to_ctfd(challenge, CTFD_URL, API_KEY)
        print(f"{'✅' if result else '❌'} Uploaded: {challenge['name']}")

