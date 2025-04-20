import random
import json
import requests
import base64
import hashlib
import os
import zipfile
import tempfile
from faker import Faker

class ChallengeGeneratorHard:
    def __init__(self):
        self.fake = Faker()
        self.difficulty = "Hard"
        self.value_range = (400, 500)
        self.max_attempts = 3

        self.categories = {
            "Web": [
                "SQL Injection Chain",
                "JWT Key Confusion",
                "Deserialization Attack",
                "CSP Bypass + XSS",
                "Server-Side Template Injection"
            ],
            "Crypto": [
                "RSA Fault Injection",
                "Custom Block Cipher Weakness",
                "PRNG Bias Exploit",
                "Elliptic Curve Twist Attack",
                "Timing Attack Side Channel"
            ],
            "Reverse Engineering": [
                "Obfuscated Binary",
                "Self-Modifying Code",
                "Anti-Debugging Techniques",
                "VM-Based Obfuscation",
                "Packed Executable with Junk Code"
            ]
        }

    def generate_flag(self):
        return f"CTF{{{self.fake.lexify(text='????????????', letters='abcdef1234567890')}}}"

    def generate_challenge(self, category, challenge_name):
        flag = self.generate_flag()
        description = self._generate_description(category, challenge_name)
        hint = self._generate_hint(category, challenge_name)

        file_content = f"Challenge: {challenge_name}\nFind the flag: {flag}".encode()
        encoded_file = base64.b64encode(file_content).decode()

        challenge = {
            "name": f"[{self.difficulty}] {challenge_name}",
            "category": category,
            "description": description,
            "value": random.randint(*self.value_range),
            "max_attempts": self.max_attempts,
            "type": "standard",
            "state": "visible",
            "flags": [{"type": "static", "content": flag}],
            "files": [{
                "name": f"{challenge_name.lower().replace(' ', '_')}.txt",
                "content": encoded_file,
                "type": "text/plain",
                "encoding": "base64"
            }],
            "hints": [hint],
            "requirements": None
        }

        return challenge

    def _generate_description(self, category, name):
        if category == "Web":
            return f"A web app has a vulnerability related to {name}. Explore the HTTP behaviors and exploit the flaw to find the flag."
        elif category == "Crypto":
            return f"A custom cryptographic system was implemented using {name}. Analyze the algorithm and recover the secret."
        elif category == "Reverse Engineering":
            return f"Analyze this binary which implements {name}. Understand the code behavior and extract the embedded flag."
        else:
            return "Explore and exploit the vulnerability to find the flag."

    def _generate_hint(self, category, name):
        hints = {
            "Web": [
                "Check for chained vulnerabilities.",
                "Look into the JWT validation method.",
                "Try to interfere with the deserialization flow.",
                "Is there a CSP? Can you bypass it?",
                "Use the template syntax and explore variables."
            ],
            "Crypto": [
                "Think about what happens when decryption fails.",
                "Compare patterns in the ciphertext blocks.",
                "Explore statistical anomalies.",
                "Use a small curve and try invalid inputs.",
                "Observe how execution time varies with input."
            ],
            "Reverse Engineering": [
                "Trace the control flow carefully.",
                "Watch for instructions modifying themselves.",
                "Try using a debugger with anti-debug countermeasures.",
                "Look for bytecode or strange VM logic.",
                "Unpack and analyze code segments slowly."
            ]
        }
        return {"content": random.choice(hints[category]), "cost": 50}

    def upload_to_ctfd(self, challenge, ctfd_url, api_key):
        headers = {
            "Authorization": f"Token {api_key}",
            "Content-Type": "application/json"
        }

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
            print(f"❌ Challenge create failed: {response.text}")
            return False

        challenge_id = response.json()["data"]["id"]

        # Upload flag
        flag_data = {
            "content": challenge["flags"][0]["content"],
            "type": "static",
            "challenge_id": challenge_id
        }
        requests.post(f"{ctfd_url}/api/v1/flags", headers=headers, json=flag_data)

        # Upload file
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

                requests.post(f"{ctfd_url}/api/v1/files", headers={"Authorization": f"Token {api_key}"}, files=files)

        # Add hints
        for hint in challenge["hints"]:
            requests.post(
                f"{ctfd_url}/api/v1/hints",
                headers=headers,
                json={
                    "challenge_id": challenge_id,
                    "content": hint["content"],
                    "cost": hint["cost"]
                }
            )

        return True


if __name__ == "__main__":
    generator = ChallengeGeneratorHard()

    all_challenges = []

    for category, names in generator.categories.items():
        used_names = set()
        while len(used_names) < 5:
            name = random.choice(names)
            if name not in used_names:
                challenge = generator.generate_challenge(category, name)
                all_challenges.append(challenge)
                used_names.add(name)

    with open("ctf_hard_challenges.json", "w") as f:
        json.dump(all_challenges, f, indent=2)
    print("✅ Generated 15 unique [Hard] challenges across Web, Crypto, and Reverse Engineering.")

    # Upload (optional - add your CTFd URL and API Key)
    CTFD_URL = "http://13.61.255.221:8000"
    API_KEY = "ctfd_5b508b033c76264a588cfd9e2647fe3c450c002439bc2c4684937ff24cfa9b39"

    for challenge in all_challenges:
        success = generator.upload_to_ctfd(challenge, CTFD_URL, API_KEY)
        print(f"{'✅' if success else '❌'} Uploaded: {challenge['name']}")

