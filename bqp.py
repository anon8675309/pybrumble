#!/usr/bin/env python3
from logging import debug, info, error, basicConfig, INFO, DEBUG
from struct import pack
try:
    from pure25519.basic import bytes_to_clamped_scalar
    from pure25519.dh import dh_finish
    from pure25519.ed25519_oop import create_keypair, SigningKey, VerifyingKey
    from pure25519.eddsa import H as dhh
    from blake256.blake256 import blake_hash  # Blake2 wasn't added to hashlib in Python 3.4.3
except ImportError as e:
    print("%s" % e)
    print("To install dependencies: pip3 install pure25519 blake256")
    from sys import exit
    exit(1)


PROTOCOL_VERSION = 2;
COMMIT_LENGTH = 16;
TRANSPORT_ID_BLUETOOTH = 0;
TRANSPORT_ID_LAN = 1;
RECORD_TYPE_KEY = 0
RECORD_TYPE_CONFIRM = 1
RECORD_TYPE_ABORT = 2


"""
Takes an IP in quad dotted notation and converts it to bytes
"""
def str_to_ip(ip):
    return b"".join([bytes([int(x)]) for x in ip.split(".")])

"""
Takes bytes representing an IP address, and returns it in quad dotted notation
"""
def ip_to_str(b):
    return ".".join([str(int(x)) for x in b])

"""
Helper function to extract the wifi IP/port from a scan payload.  If no
wifi info in detected, a tuple of (None, None) is returned.

:param scan_payload: scan payload we're extracting data from
:type scan_payload: list
:returns: IP and port
:rtype: tuple (string, int)
"""
def obtain_wifi_info(scan_payload):
    transports = scan_payload[2:]
    for t in transports:
        if t[0] == TRANSPORT_ID_LAN:
            return ip_to_str(t[1]), t[2]
    return None, None

"""
Takes a bluetooth address in a string of colon delimited hex values and
converts it into a binary string.
"""
def str_to_bt(bt):
	return b"".join([bytes([int(x, 16)]) for x in bt.split(":")])

"""
Takes a binary string of bytes and converts them into a human readable
colon delimitied string of hex values.
"""
def bt_to_str(bt):
    return ":".join(["%0.2x" % x for x in bt])

"""
This function abstracts away the need to know what algorithm is being used for
the asymmetric keys.

:returns: Private and public keys
:rtype: tuple (`py:SigningKey`, `py:VerifyingKey`)
"""
def gen_keypair():
	return create_keypair()

"""
Saves keys to files using the to_ascii() method from pure25519 (which
actually stores the seed, not the key, but everything can be re-generated
from the seed).

:param priv: Private key
:type priv: `py:SigningKey`
:param pub: Public key
:type pub: `py:VerifyingKey`
:param priv_file: Name of the file with the private key
:type priv_file: string
:param priv_file: Name of the file with the public key
:type pub_file: string
:returns: None
:rtype: None
"""
def save_keys(priv, pub, priv_file, pub_file):
    with open(priv_file, "wb") as f:
        f.write(priv.to_ascii(encoding="base64"))
    with open(pub_file, "wb") as f:
        f.write(pub.to_ascii(encoding="base64"))

"""
Reads the seeds from the files, and reconstructs the keys accordingly.

:param priv_file: Name of the file with the private key
:type priv_file: string
:param priv_file: Name of the file with the public key
:type pub_file: string
:returns: private and public keys
:rtype: tuple (`py:SigningKey`, `py:VerifyingKey`)
"""
def read_keys(priv_file, pub_file):
    with open(priv_file, "rb") as f:
        priv = SigningKey(f.read(), encoding="base64")
    with open(pub_file, "rb") as f:
        pub = VerifyingKey(f.read(), encoding="base64")
    return priv, pub


"""
This function returns a commitment to a public key.

:param pub: The public key (use to_bytes() if you have a `py:VerifyingKey`)
:type pub: bytes
:returns: 16 byte commitment to publish a matching key later
:rtype: bytes
"""
def create_commitment(pub):
	# Commitment is defined as the first 16 bytes of the hash of COMMIT + pubkey
	return blake_hash(b"COMMIT" + pub)[0:16]

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
:returns: The data to encode and jam into the QR code
:rtype: list
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

"""
The pure25519 library doesn't store the private key, instead it stores a seed
which is hashed, and then the bytes of the hash are converted to a scalar.
Because of this nonsense, we can't just access priv.key, instead we need to go
through this hashing song and dance.  This function does that for you.

:param priv: SigningKey object (the closest thing pure25519 has to a secret key)
:type priv: SigningKey
:returns: private key
:rtype: int
"""
def _get_private_key_as_scalar(priv):
    h = dhh(priv.sk_s[:32])  # Hash the seed (the first 32 bytes of sk_s)
    a_bytes = h[:32]       # The first 32 bytes of the hash is used as the secret key
    return bytes_to_clamped_scalar(a_bytes)  # return key as a scalar

"""
Calculates the shared secret for Alice based on her keypair and Bob's public key

:param priv: Alice's private key
:type priv: `py:SigningKey`
:param pub_a: Alice's public key
:type pub_a: bytes
:param pub_b: Bob's public key
:type pub_b: bytes
:returns: Shared secret
:rtype: bytes
"""
def calculate_shared_secret_alice(priv, pub_a, pub_b):
    return HASH([b"SHARED_SECRET", DH(priv, pub_b), pub_a, pub_b])

"""
Calculates the shared secret for Bob based on his keypair and Alice's public key

:param priv: Bob's private key
:type priv: `py:SigningKey`
:param pub_a: Bob's public key
:type pub_a: bytes
:param pub_b: Alice's public key
:type pub_b: bytes
:returns: Shared secret
:rtype: bytes
"""
def calculate_shared_secret_bob(priv, pub_a, pub_b):
    return HASH([b"SHARED_SECRET", DH(priv, pub_a), pub_a, pub_b])

"""
Diffie-Hellman function

:param priv: Private key
:type priv: `py:SigningKey`
:param pub: Public key
:type pub: bytes
:returns: shared secret
:rtype: bytes
"""
def DH(priv, pub):
    return dh_finish(_get_private_key_as_scalar(priv), pub)

"""
Hash function

:param m: Message (data) to be hashed
:type m: bytes
:returns: Hash of data
:rtype: bytes
"""
def H(m):
    return blake_hash(m)

"""
Multi-argument hash function.

:param inputs: List of inputs to hash
:type inputs: list of bytes
:returns: Hash of inputes
:rtype: bytes
"""
def HASH(inputs):
    m = b""
    for i in inputs:
        m += pack(">I", len(i))
        m += i
    return H(m)

"""
Message Authentication Code (keyed hash) function.

:param k: Secret key
:type k: bytes
:param m: Message
:type m: bytes
:returns: MAC of message
:rtype: bytes
"""
def MAC(k, m):
	return H(k + pack(">I", len(m)) + m)

"""
Key derivation function, takes a key and multiple inputs to generate
new keys.

:param inputs: List of inputs to hash
:type inputs: list of bytes
:returns: Hash of inputes
:rtype: bytes
"""
def KDF(k, inputs):
    m = b""
    for i in inputs:
        m += pack(">I", len(i))
        m += i
    return MAC(k, m)

"""
Generate a record.
"""
def gen_record(record_type, data, protocol_version=PROTOCOL_VERSION):
	header = pack(">B", PROTOCOL_VERSION)
	header += pack(">B", record_type)
	header += pack(">H", len(data))
	return header + data

"""
This will generate a confirmation blob to ensure the peer received the
correct public key.

:param ss: Shared secret
:type ss: bytes
:param q_a: Alice's scan payload
:type q_a: bytes
:param pub_a: Alice's public key
:type pub_a: bytes
:param q_b: Bob's scan payload
:type q_b: bytes
:param pub_b: Bob's public key
:type pub_b: bytes
:returns: Confirmation blob
:rtype: bytes
"""
def gen_confirmation_alice(ss, q_a, pub_a, q_b, pub_b):
	confirmation_key = KDF(ss, [b"CONFIRMATION_KEY"])
	return KDF(confirmation_key,
                   [b"CONFIRMATION_MAC", q_a, pub_a, q_b, pub_b])

"""
This will generate a confirmation blob to ensure the peer received the
correct public key.

:param ss: Shared secret
:type ss: bytes
:param q_a: Alice's scan payload
:type q_a: bytes
:param pub_a: Alice's public key
:type pub_a: bytes
:param q_b: Bob's scan payload
:type q_b: bytes
:param pub_b: Bob's public key
:type pub_b: bytes
:returns: Confirmation blob
:rtype: bytes
"""
def gen_confirmation_bob(ss, q_a, pub_a, q_b, pub_b):
	confirmation_key = KDF(ss, [b"CONFIRMATION_KEY"])
	return KDF(confirmation_key,
                   [b"CONFIRMATION_MAC", q_b, pub_b, q_a, pub_a])
