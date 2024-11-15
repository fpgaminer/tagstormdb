#!/usr/bin/env python3
import struct
import argparse
import xxhash
from tqdm import tqdm


parser = argparse.ArgumentParser(description='Truncate a log file')
parser.add_argument('--input', type=str, help='The input log file', required=True)
parser.add_argument('--output', type=str, help='The output log file', required=True)
parser.add_argument('--num-logs', type=int, help='The number of logs to truncate', required=True)


def main():
	args = parser.parse_args()

	with open(args.input, 'rb') as infile, open(args.output, 'wb') as outfile:
		count = struct.unpack('<Q', infile.read(8))[0]
		print("Number of input logs:", count)

		outfile.write(struct.pack('<Q', args.num_logs))

		for i in tqdm(range(args.num_logs)):
			timestamp = struct.unpack('<q', infile.read(8))[0]
			user_id = read_vli(infile)
			action = infile.read(1)

			data = bytearray()
			data.extend(struct.pack('<q', timestamp))
			data.extend(write_vli(user_id))
			data.extend(action)

			if action == b'\x00':  # AddTag
				a = read_vli(infile)
				data.extend(write_vli(a))
				data.extend(infile.read(a))
			elif action == b'\x01' or action == b'\x02' or action == b'\x03':  # RemoveTag, AddImage, RemoveImage
				a = read_vli(infile)
				data.extend(write_vli(a))
			elif action == b'\x04' or action == b'\x05':  # AddImageTag, RemoveImageTag
				a = read_vli(infile)
				b = read_vli(infile)
				data.extend(write_vli(a))
				data.extend(write_vli(b))
			elif action == b'\x06' or action == b'\x07':  # AddAttribute, RemoveAttribute
				a = read_vli(infile)
				b = read_vli(infile)
				c = read_vli(infile)
				data.extend(write_vli(a))
				data.extend(write_vli(b))
				data.extend(write_vli(c))
			else:
				raise ValueError("Invalid action")
			
			checksum = infile.read(1)
			expected_checksum = xxhash.xxh3_64(data).intdigest() & 0xff
			assert checksum == struct.pack('B', expected_checksum)
			data.extend(checksum)

			outfile.write(data)


def read_vli(file):
	first_byte = file.read(1)
	if not first_byte:
		raise EOFError
	first_byte = ord(first_byte)
	if first_byte <= 0xfc:
		return first_byte
	elif first_byte == 0xfd:
		return struct.unpack('<H', file.read(2))[0]
	elif first_byte == 0xfe:
		return struct.unpack('<I', file.read(4))[0]
	else:
		return struct.unpack('<Q', file.read(8))[0]


def write_vli(value):
	if value <= 0xfc:
		return struct.pack('B', value)
	elif value <= 0xffff:
		return struct.pack('<BH', 0xfd, value)
	elif value <= 0xffffffff:
		return struct.pack('<BI', 0xfe, value)
	else:
		return struct.pack('<BQ', 0xff, value)


def read_string(file):
	length = read_vli(file)
	return file.read(length).decode('utf-8')


if __name__ == "__main__":
	main()