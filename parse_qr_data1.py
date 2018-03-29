#!/usr/bin/env python3
from argparse import ArgumentParser
from base64 import b64decode
from bdf import extract_data, ip_to_str, bt_to_str
from bqp import TRANSPORT_ID_BLUETOOTH, TRANSPORT_ID_LAN
from binascii import hexlify
from log_helper import setup_logging
from logging import debug, info, error, basicConfig, INFO, DEBUG
from pprint import pprint

def parse_data(d):
	version = d[0]
	debug("Version: %d" % version)
	if version == 2:
		debug(repr(d))
		commitment = d[1]
		print("Commitment to key (first 16 bytes of hash of key): %s" % hexlify(commitment).decode())
		transports = d[2:]
		for transport in transports:
			transport_id = transport[0]
			transport_properties = transport[1:]
			if transport_id == TRANSPORT_ID_BLUETOOTH:
				print("Transport ID: %d (BLUETOOTH)" % transport_id)
				print("Bluetooth address: %s" % bt_to_str(transport_properties[0]))
			elif transport_id == TRANSPORT_ID_LAN:
				print("Transport ID: %d (LAN)" % transport_id)
				ip = transport_properties[0]
				port = transport_properties[1]
				print("IP/Port: %s:%d" % (ip_to_str(ip), port))
	else:
		raise Exception("Version %d not implemented")


"""
Example usage:
./parse_qr_data1.py -v YCECURAS2z68O4S+UdA/Z6tdbbdQYCEAUQa8dl5YYIKAgA== 
"""
if __name__ == "__main__":
	parser = ArgumentParser(description='Decodes and displays information extracted from QR code data')
	parser.add_argument('data', help=('The data from the QR code'))
	group = parser.add_mutually_exclusive_group()
	group.add_argument("-v", "--verbose", action="count", help=('Verbose output (for debugging issues)'))
	group.add_argument("-q", "--quiet", action="count", help=('Quiet down the output'))
	args = parser.parse_args()
	
	setup_logging(args)

	data = b64decode(args.data)
	obj, remainder = extract_data(data)
	parse_data(obj)
	info("%d bytes remaining" % len(remainder))
