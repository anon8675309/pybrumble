#!/usr/bin/env python3
from argparse import ArgumentParser
from base64 import b64encode
from bdf import encode_data, str_to_ip, str_to_bt
from bqp import PROTOCOL_VERSION, TRANSPORT_ID_BLUETOOTH, TRANSPORT_ID_LAN, \
		gen_keypair, create_commitment, gen_scan_payload
from log_helper import setup_logging

try:
    from pure25519.ed25519_oop import create_keypair
    from blake256.blake256 import blake_hash  # Blake2 wasn't added to hashlib in Python 3.4.3
    from pyqrcode import create
    import png  # Used by pyqrcode to output image
except ImportError as e:
    print("%s" % e)
    print("To install dependencies: pip3 install pure25519 blake256 pyqrcode pypng")
    from sys import exit
    exit(1)



DEFAULT_QR_CODE_FILENAME="contact_exchange.png"
"""
This program will generate an ephemeral keypair, as described in section 2 of the BQP specification.

Example usage:
./exchange_contacts.py
"""
if __name__ == "__main__":
	parser = ArgumentParser(description='Generate ephemerial keys and do an exchange')
	parser.add_argument("-b", "--bluetooth", default=None, help=("Specify bluetooth address (colon "
					"delimited hex values), which enables the bluetooth transport layer"))
	parser.add_argument("-l", "--lan", default=None, help=("Specify IP address and port (colon "
					"separated), which enables the LAN transport layer"))
	parser.add_argument("-o", "--output", default=DEFAULT_QR_CODE_FILENAME,
		help=("Specify the output filename for the QR code (Default: %s)" % DEFAULT_QR_CODE_FILENAME))
	group = parser.add_mutually_exclusive_group()
	group.add_argument("-v", "--verbose", action="count", help=('Verbose output (for debugging issues)'))
	group.add_argument("-q", "--quiet", action="count", help=('Quiet down the output'))
	args = parser.parse_args()

	setup_logging(args)

	priv, pub = gen_keypair()
	commitment = create_commitment(pub)
	scan_payload = gen_scan_payload(commitment, args.bluetooth, args.lan)

	wire_encoded_payload = encode_data(scan_payload)
	b64_encoded_payload = b64encode(wire_encoded_payload)
	print(b64_encoded_payload.decode())
	qrcode = create(b64_encoded_payload)
	qrcode.png(args.output, scale=8)

	# The next phase of the key exchange is done online, which is described in section 4 of the bqp spec
