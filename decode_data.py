#!/usr/bin/env python3
from argparse import ArgumentParser
from base64 import b64decode
from bdf import extract_data
from binascii import hexlify
from log_helper import setup_logging
from logging import debug, info, error, basicConfig, INFO, DEBUG
from pprint import pprint


"""
Example usage:
./decode_data.py -v YCECURAS2z68O4S+UdA/Z6tdbbdQYCEAUQa8dl5YYIKAgA== 
./decode_data.py -v YCECURDMF8G+lLF9x7bMe59fn9vNYCEAUQa8dl5YYIKAYCEBUQSsEABvJAAA30KAgA==
"""
if __name__ == "__main__":
	parser = ArgumentParser(description='Decodes one item from a stream and displays it')
	parser.add_argument('data', help=('The data'))
	group = parser.add_mutually_exclusive_group()
	group.add_argument("-v", "--verbose", action="count", help=('Verbose output (for debugging issues)'))
	group.add_argument("-q", "--quiet", action="count", help=('Quiet down the output'))
	args = parser.parse_args()
	
	setup_logging(args)

	data = b64decode(args.data)
	obj, remainder = extract_data(data)
	pprint(obj)
	info("%d bytes remaining" % len(remainder))
