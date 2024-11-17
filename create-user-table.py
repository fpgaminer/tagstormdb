#!/usr/bin/env python3
import struct
import xxhash
import argparse
from hashlib import sha256, scrypt
import string
import secrets


parser = argparse.ArgumentParser(description='Create a user table file')
parser.add_argument('--filename', type=str, help='The filename of the user table')
parser.add_argument('--username', type=str, default='admin', help='The username of the user')
parser.add_argument('--scopes', type=str, default='users/*/scopes/change', help='The scopes of the user')
args = parser.parse_args()


def main():
	args = parser.parse_args()

	# Generate a secure random password
	alphabet = string.ascii_letters + string.digits
	password = ''.join(secrets.choice(alphabet) for i in range(20))
	login_key = login_key_from_password(args.username, password)
	hashed_login_key = sha256(login_key).digest()

	with open(args.filename, 'wb') as f:
		# Write the number of users (u64 little endian)
		f.write(struct.pack('<Q', 1))

		# Prepare the buffer for the user entry
		buffer = bytearray()

		# Write username
		write_string(buffer, args.username)

		# Write hashed_login_key (32 bytes)
		buffer.extend(hashed_login_key)

		# Write scopes
		write_string(buffer, args.scopes)

		# Calculate checksum
		checksum = xxhash.xxh3_64(buffer).intdigest() & 0xffff
		buffer.extend(struct.pack('<H', checksum))

		# Write the buffer to the file
		f.write(buffer)

	print("Password:", password)


def login_key_from_password(username: str, password: str) -> bytes:
	# Scrypt the password
	login_key = scrypt(password.encode('utf-8'), salt=username.encode('utf-8'), n=2**16, r=8, p=1, maxmem=128*1024*1024, dklen=32)

	return login_key


def write_vli(buffer, n):
	if n <= 0xfc:
		buffer.append(n)
	elif n <= 0xffff:
		buffer.append(0xfd)
		buffer.extend(struct.pack('<H', n))
	elif n <= 0xffffffff:
		buffer.append(0xfe)
		buffer.extend(struct.pack('<I', n))
	else:
		buffer.append(0xff)
		buffer.extend(struct.pack('<Q', n))


def write_string(buffer, s):
	s_bytes = s.encode('utf-8')
	len_s = len(s_bytes)
	write_vli(buffer, len_s)
	buffer.extend(s_bytes)


if __name__ == "__main__":
	main()