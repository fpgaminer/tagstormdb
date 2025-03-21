#!/usr/bin/env python3
from base64 import b32encode
import time
import argparse
import requests
import json
from pathlib import Path
import hmac
import hashlib
from datetime import datetime

parser = argparse.ArgumentParser(description="Create an invitation code")
parser.add_argument("--secrets", type=str, default="secrets.json", help="Path to secrets file")
parser.add_argument("--duration", type=int, default=(24*60*60), help="Duration of the invitation code in seconds")

def main():
	args = parser.parse_args()

	# Get current time and make sure it's valid
	current_time = int(time.time())
	google_time = get_google_time()
	if abs(current_time - google_time) > 60:
		print(f"Local time is off by more than 60 seconds from Google time. Local time: {current_time}, Google time: {google_time}")
		exit(1)
	
	# Calculate expiration timestamp
	expiration_time = current_time + args.duration
	print(f"Invitation code will expire at {datetime.utcfromtimestamp(expiration_time).strftime('%A, %B %d, %Y at %I:%M %p UTC')}")

	# Construct invitation code
	expiration_time_bytes = expiration_time.to_bytes(8, byteorder='little')
	invitation_code = expiration_time_bytes

	# Load secrets
	secrets = json.loads(Path(args.secrets).read_text())
	server_secret = bytes.fromhex(secrets["server_secret"])
	assert len(server_secret) >= 32, "Server secret must be at least 32 bytes long"

	# Derive key
	key = derive_key(server_secret, b"user-invitation-auth")

	# Compute authentication code
	auth = compute_authentication_code(b"user-invitation-code", invitation_code, key)
	invitation_code += auth

	# Encode invitation code
	invitation_code_b32 = b32encode(invitation_code).decode().lower()

	print(f"Invitation code: {invitation_code_b32}")


def derive_key(master_key: bytes, purpose: bytes) -> bytes:
	assert len(master_key) >= 32
	assert len(purpose) >= 0

	hmac_obj = hmac.new(master_key, purpose, digestmod=hashlib.sha512)
	key = hmac_obj.digest()

	return key

def compute_authentication_code(aad: bytes, data: bytes, key: bytes) -> bytes:
	assert len(key) >= 32

	hmac_obj = hmac.new(key, None, digestmod=hashlib.sha512)
	hmac_obj.update(aad)
	hmac_obj.update(data)
	hmac_obj.update(len(aad).to_bytes(8, byteorder='little'))
	hmac_obj.update(len(data).to_bytes(8, byteorder='little'))

	# Truncate to 256 bits
	computed_hmac = hmac_obj.digest()
	assert len(computed_hmac) == 64
	computed_hmac = computed_hmac[:32]

	return computed_hmac


def get_google_time() -> int:
	response = requests.get("https://www.google.com", timeout=5)
	date_header = response.headers["Date"]
	from email.utils import parsedate_to_datetime
	server_time = parsedate_to_datetime(date_header).timestamp()
	return int(server_time)


if __name__ == "__main__":
	main()