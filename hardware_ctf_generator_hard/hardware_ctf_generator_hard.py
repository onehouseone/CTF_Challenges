import random
import json
import requests
import base64
import hashlib
import os
import zipfile
import tempfile
from faker import Faker

class HardwareCTFGeneratorHard:
    def __init__(self):
        self.fake = Faker()
        self.categories = [
            "Advanced Firmware Analysis",
            "Side Channel Attacks",
            "Glitching & Fault Injection",
            "Complex JTAG/UART Exploitation",
            "Custom Hardware Protocols"
        ]
        self.difficulty = "Hard"
        self.value_range = (400, 500)
        self.max_attempts = 3
        self.challenge_types = [
            "Timing Attack on Encrypted EEPROM",
            "Firmware Crypto Key Extraction",
            "Power Analysis Dump",
            "Fault Injection Firmware Bypass",
            "Custom Bus Protocol Decoder",
            "JTAG Exploit with Lock Bits",
            "UART Command Injection",
            "PCB Reverse Engineering (Multi-layer)"
        ]

    def generate_random_flag(self):
        prefix = random.choice(["FLAG", "CTF"])
        secret = self.fake.lexify(text='?????????????????', letters='abcdef1234567890')
        return f"{prefix}{{{secret}}}"

    def generate_power_analysis_dump(self, flag):
        # Simulate a side-channel trace with flag buried
        trace = [random.randint(0, 255) for _ in range(1000)]
        pos = random.randint(300, 700)
        for i, b in enumerate(flag.encode()):
            trace[pos + i] = b
        return json.dumps(trace)

    def generate_firmware_with_crypto_flag(self, flag):
        key = self.fake.sha1()[:16].encode()
        encrypted = base64.b64encode(bytes([b ^ key[i % len(key)] for i, b in enumerate(flag.encode())]))
        return encrypted.decode()

    def generate_jtag_dump(self, flag):
        raw = bytearray([random.randint(0, 255) for _ in range(512)])
        raw[120:120 + len(flag)] = flag.encode()
        return raw

    def generate_uart_data(self, flag):
        lines = [
            "Booting device...",
            "UART connected at 115200",
            "Admin console opened...",
            f"SECRET_CMD >> {flag}",
            "Session closed"
        ]
        return "\n".join(lines).encode()

    def generate_pcb_info(self, flag):
        layers = {
            "top_layer": base64.b64encode(f"Signal traces and pinout\nFLAG: {flag}".encode()).decode(),
            "bottom_layer": base64.b64encode(self.fake.text().encode()).decode()
        }
        return layers

    def generate_unique_challenges(self, n=5):
        selected_types = random.sample(self.challenge_types, k=n)
        challenges = []

        for challenge_type in selected_types:
            flag = self.generate_random_flag()
            challenge = {
                "name": f"[Hard] {challenge_type}",
                "category": random.choice(self.categories),
                "description": "",
                "value": random.randint(*self.value_range),
                "max_attempts": self.max_attempts,
                "type": "standard",
                "state": "visible",
                "tags": [{"value": "Hard"}],
                "flags": [{"type": "static", "content": flag}],
                "files": [],
                "hints": []
            }

            # Generate specific files & descriptions
            if "Power Analysis" in challenge_type:
                challenge["description"] = (
                    "You intercepted a side-channel power consumption trace from a secure device. "
                    "It appears to leak some information. Can you analyze it to retrieve the flag?"
                )
                trace = self.generate_power_analysis_dump(flag)
                challenge["files"].append({
                    "name": "power_trace.json",
                    "content": trace,
                    "type": "application/json"
                })
                challenge["hints"].append({"content": "Look for unusual patterns in mid-section of the trace.", "cost": 100})

            elif "Firmware Crypto" in challenge_type:
                challenge["description"] = (
                    "This firmware contains a crypto routine protecting a flag. "
                    "Reverse engineer the obfuscation or XOR encryption to recover it."
                )
                encrypted_flag = self.generate_firmware_with_crypto_flag(flag)
                challenge["files"].append({
                    "name": "encrypted_firmware.bin",
                    "content": encrypted_flag,
                    "type": "application/octet-stream"
                })
                challenge["hints"].append({"content": "It's XOR-encrypted with a short static key.", "cost": 100})

            elif "JTAG" in challenge_type:
                challenge["description"] = (
                    "You've managed to dump memory over a JTAG interface protected by lock bits. "
                    "Analyze the raw dump and extract what matters."
                )
                dump = self.generate_jtag_dump(flag)
                encoded = base64.b64encode(dump).decode()
                challenge["files"].append({
                    "name": "jtag_memory_dump.bin",
                    "content": encoded,
                    "type": "application/octet-stream",
                    "encoding": "base64"
                })
                challenge["hints"].append({"content": "Try 'strings' or hex viewers to locate ASCII content.", "cost": 100})

            elif "UART" in challenge_type:
                challenge["description"] = (
                    "A debug UART interface gave us this log. A secret command was executed. "
                    "Can you find out what it was?"
                )
                uart_log = self.generate_uart_data(flag)
                encoded = base64.b64encode(uart_log).decode()
                challenge["files"].append({
                    "name": "uart_debug.log",
                    "content": encoded,
                    "type": "text/plain",
                    "encoding": "base64"
                })
                challenge["hints"].append({"content": "Check for commands prefixed with SECRET_", "cost": 100})

            elif "PCB" in challenge_type:
                challenge["description"] = (
                    "We extracted multilayer data from a suspicious PCB. One of the layers holds a flag. "
                    "Can you decode the image or text data?"
                )
                pcb_data = self.generate_pcb_info(flag)
                for name, content in pcb_data.items():
                    challenge["files"].append({
                        "name": f"{name}.dat",
                        "content": content,
                        "type": "application/octet-stream",
                        "encoding": "base64"
                    })
                challenge["hints"].append({"content": "Inspect the 'top_layer'.", "cost": 100})

            else:
                challenge["description"] = "This hard challenge involves hardware-level analysis. Details are classified."
                challenge["hints"].append({"content": "Start with basic forensic tools.", "cost": 100})

            challenges.append(challenge)

        return challenges

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

        # Add tags
        for tag in challenge.get("tags", []):
            requests.post(
                f"{ctfd_url}/api/v1/tags",
                headers=headers,
                json={"challenge_id": challenge_id, "value": tag["value"]}
            )

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
    generator = HardwareCTFGeneratorHard()
    challenges = generator.generate_unique_challenges(n=5)

    # Save locally
    with open("hardware_ctf_hard.json", "w") as f:
        json.dump(challenges, f, indent=2)

    print("✅ Generated 5 Hard difficulty Hardware CTF challenges.")

    # Optionally upload to CTFd
    CTFD_URL = "http://13.61.255.221:8000"
    API_KEY = "ctfd_5b508b033c76264a588cfd9e2647fe3c450c002439bc2c4684937ff24cfa9b39"

    for challenge in challenges:
        result = generator.upload_to_ctfd(challenge, CTFD_URL, API_KEY)
        print(f"{'✅' if result else '❌'} Uploaded: {challenge['name']}")

