#!/usr/bin/env python3
from bdf import encode_data, str_to_ip, str_to_bt
try:
    from pure25519.ed25519_oop import create_keypair
    from blake256.blake256 import blake_hash  # Blake2 wasn't added to hashlib in Python 3.4.3
except ImportError as e:
    print("%s" % e)
    print("To install dependencies: pip3 install pure25519 blake256 pyqrcode pypng")
    from sys import exit
    exit(1)


PROTOCOL_VERSION = 2;
RECORD_HEADER_LENGTH = 6;
RECORD_HEADER_PAYLOAD_LENGTH_OFFSET = 2;
COMMIT_LENGTH = 16;
CONNECTION_TIMEOUT = 20 * 1000;
TRANSPORT_ID_BLUETOOTH = 0;
TRANSPORT_ID_LAN = 1;
SHARED_SECRET_LABEL = "org.briarproject.bramble.keyagreement/SHARED_SECRET";
MASTER_SECRET_LABEL = "org.briarproject.bramble.keyagreement/MASTER_SECRET";


"""
This function abstracts away the need to know what algorithm is being used for
the asymmetric keys.

:returns: Private and public keys
:rtype: tuple (`py:ed25519_oop`, `py:ed25519_oop`)
"""
def gen_keypair():
	return create_keypair()

"""
This function returns a commitment to a public key.

:param pub: The public key
:type pub: `py:ed25519_oop`
:returns: 16 byte commitment to publish a matching key later
:rtype: bytes
"""
def create_commitment(pub):
	# Commitment is defined as the first 16 bytes of the hash of COMMIT + pubkey
	return blake_hash(b"COMMIT" + pub.to_bytes())[0:16]

"""
This will generate a scan payload which can then be encoded according to
the bdf specifications, base64 encoded and then put in a QR code for exchange.

:param commitment: The commitment for the public key
:type commitment: bytes
:param bluetooth_addr: Hex encoded, colon delimited bluetooth address (e.g.
            "12:34:ca:fe:d0:0d") or None if bluetooth is not supported
:type bluetooth_addr: string
:param lan_addr_port: IP address in dotted quad format, followed by the port,
            and separated by a colon (e.g. "192.168.0.99:7331"), or None if
            LAN is not supported
:type lan_addr_port: string
"""
def gen_scan_payload(commitment, bluetooth_addr=None, lan_addr_port=None):
	scan_payload = [PROTOCOL_VERSION, commitment]
	if bluetooth_addr:  # If Bluetooth is supported
		scan_payload.append([TRANSPORT_ID_BLUETOOTH, str_to_bt(bluetooth_addr)])
	if lan_addr_port:  # If LAN is supported
		ip, port = lan_addr_port.split(":")
		ipv4_addr = str_to_ip(ip)
		scan_payload.append([TRANSPORT_ID_LAN, ipv4_addr, int(port)])
	# This is an example of what a commitment might look like
	#[2,
	# b'\xcc\x17\xc1\xbe\x94\xb1}\xc7\xb6\xcc{\x9f_\x9f\xdb\xcd',
	# [0, b'\xbcv^X`\x82'],
	# [1, b'\xac\x10\x00o', 57154]]
	return scan_payload
