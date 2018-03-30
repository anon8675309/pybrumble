#!/usr/bin/env python3
from argparse import ArgumentParser
from base64 import b64encode, b64decode
from bdf import encode_data, extract_data, bind_to_lan, open_connection, \
		recv_record, send_record
from binascii import hexlify
from bqp import PROTOCOL_VERSION, TRANSPORT_ID_BLUETOOTH, TRANSPORT_ID_LAN, \
		RECORD_TYPE_KEY, RECORD_TYPE_CONFIRM, RECORD_TYPE_ABORT, obtain_wifi_info, \
		calculate_shared_secret_alice, calculate_shared_secret_bob, \
		str_to_ip, str_to_bt, gen_keypair, create_commitment, gen_scan_payload, \
		read_keys, save_keys
from log_helper import setup_logging
from logging import debug, info, error, basicConfig, INFO, DEBUG
from sys import stdin

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
DEFAULT_PRIVATE_KEY_FILE="ephemeral"
DEFAULT_PUBLIC_KEY_FILE="ephemeral.pub"
"""
This program will generate an ephemeral keypair, as described in section 2 of the BQP specification.

Example usage:
./exchange_contacts.py
"""
if __name__ == "__main__":
	parser = ArgumentParser(description='Generates ephemerial keys (if they do not exist) and does a key exchange')
	parser.add_argument("--private-key-file", default=DEFAULT_PRIVATE_KEY_FILE,
					help=("Name/location of private key file (Default: %s)" % DEFAULT_PRIVATE_KEY_FILE))
	parser.add_argument("--public-key-file", default=DEFAULT_PUBLIC_KEY_FILE,
					help=("Name/location of public key file (Default: %s)" % DEFAULT_PUBLIC_KEY_FILE))
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

	try:
		debug("Attempting to read keys from disk...")
		priv, pub = read_keys(args.private_key_file, args.public_key_file)
		debug("Read keys from disk.  Pubkey = %s" % hexlify(pub.vk_s))
	except:
		debug("Unable to read keys from disk, generating keys...")
		priv, pub = gen_keypair()
		debug("Saving keys to disk...")
		save_keys(priv, pub, args.private_key_file, args.public_key_file)

	commitment = create_commitment(pub.to_bytes())
	my_scan_payload = gen_scan_payload(commitment, args.bluetooth, args.lan)

	wire_encoded_payload = encode_data(my_scan_payload)
	b64_encoded_payload = b64encode(wire_encoded_payload)
	print(b64_encoded_payload.decode())
	qrcode = create(b64_encoded_payload)
	qrcode.png(args.output, scale=8)

	# Read in the other person's scan_payload from stdin
	other_scan_payload, reamining_data = extract_data(b64decode(stdin.readline()))
	print(repr(other_scan_payload))

	# Now we need to make sure we're bound on the IP/port we said we'd be listening on
	ip, port = args.lan.split(":")
	s = bind_to_lan(ip, port)

	# Per section 3 of the bqp spec, we determine whether we are ALICE or BOB
	i_am_alice = commitment < other_scan_payload[1]
	print("I am %s" % ("Bob", "Alice")[i_am_alice])
	# The next phase of the key exchange is done online, which is described in section 4 of the bqp spec
	if i_am_alice:
		s.close()  # Close my connection, I want to use Bob's connection
		remote_ip, remote_port = obtain_wifi_info(other_scan_payload)
		debug("Connecting to Bob on port %d" % remote_port)
		conn = open_connection(remote_ip, remote_port)
		send_record(conn, RECORD_TYPE_KEY, pub.to_bytes())
		record = recv_record(conn)
		if record[1] == RECORD_TYPE_KEY:
			pub_b = record[2]
			# If bob's key doesn't match his commitment, we must abort
			if other_scan_payload[1] != create_commitment(pub_b):
				send_record(conn, RECORD_TYPE_ABORT, b"")
				raise Exception("Public key did not match commitment!")
			shared_secret = calculate_shared_secret_alice(priv, pub.to_bytes(), pub_b)
			debug("shared secret = %s" % shared_secret)
	else:
		debug("Waiting for Alice to connect to us on port %s..." % port)
		conn, remote_addr = s.accept()
		record = recv_record(conn)
		if record[1] == RECORD_TYPE_KEY:
			pub_a = record[2]
			# If the key doesn't match the commitment, we must abort
			if other_scan_payload[1] != create_commitment(pub_a):
				send_record(conn, RECORD_TYPE_ABORT, b"")
				raise Exception("Public key did not match commitment!")
			send_record(conn, RECORD_TYPE_KEY, pub.to_bytes())
			shared_secret = calculate_shared_secret_bob(priv, pub_a, pub.to_bytes())
			debug("shared secret = %s" % shared_secret)
