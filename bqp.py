#!/usr/bin/env python3
from bdf import encode_data, open_connection, send_record, recv_record
from constants import PROTOCOL_VERSION, COMMIT_LENGTH, TRANSPORT_ID_BLUETOOTH, \
                      TRANSPORT_ID_LAN, CONFIRMATION_KEY, CONFIRMATION_MAC, \
                      RECORD_TYPE_KEY, RECORD_TYPE_CONFIRM, RECORD_TYPE_ABORT, \
                      MASTER_KEY, SHARED_SECRET, COMMIT
from logging import debug, info, error, basicConfig, INFO, DEBUG
from struct import pack
from time import sleep
try:
    from pure25519.basic import bytes_to_clamped_scalar
    from pure25519.dh import dh_finish
    from pure25519.ed25519_oop import create_keypair, SigningKey, VerifyingKey
    from pure25519.eddsa import H as dhh
    from blake256.blake256 import blake_hash as H # Blake2 wasn't added to hashlib in Python 3.4.3
except ImportError as e:
    print("%s" % e)
    print("To install dependencies: pip3 install pure25519 blake256")
    from sys import exit
    exit(1)



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
:type priv_file: binary string
:param priv_file: Name of the file with the public key
:type pub_file: binary string
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
:returns: COMMIT_LENGTH byte commitment to publish a matching key later
:rtype: bytes
"""
def create_commitment(pub):
	# Commitment is defined as the first COMMIT_LENGTH bytes of the hash of COMMIT + pubkey
	return H(COMMIT + pub)[0:COMMIT_LENGTH]

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
:returns: Shared secret (cooked_secret using the BQP spec's terminology)
:rtype: bytes
"""
def calculate_shared_secret_alice(priv, pub_a, pub_b):
    raw_secret = DH(priv, pub_b)
    return HASH([SHARED_SECRET,
                 raw_secret,
                 encode_data(PROTOCOL_VERSION),
                 pub_a,
                 pub_b])

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
    raw_secret = DH(priv, pub_a)
    return HASH([SHARED_SECRET,
                 raw_secret,
                 encode_data(PROTOCOL_VERSION),
                 pub_a,
                 pub_b])

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
This will generate a confirmation blob to ensure the peer received the
correct public key.

:param ss: Shared secret (aka cooked_secret)
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
	confirmation_key = KDF(ss, [CONFIRMATION_KEY])
	return KDF(confirmation_key,
                   [CONFIRMATION_MAC, q_a, pub_a, q_b, pub_b])

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
	confirmation_key = KDF(ss, [CONFIRMATION_KEY])
	return KDF(confirmation_key,
                   [CONFIRMATION_MAC, q_b, pub_b, q_a, pub_a])

def connect_to_peer(scan_payload):
    """
    Connect to the peer obtained from the scan payload. This includes a few
    retries in case the peer has not yet started listening on the network. This
    raises an exception if it can't connect to the peer after several attempts.

    :param scan_payload: decoded scan payload from the peer's QR code
    :type scan_payload: list
    :returns: connection to the peer
    :rtype: :class:`py:socket`
    """
    remote_ip, remote_port = obtain_wifi_info(scan_payload)
    debug("Connecting to Bob on port %d" % remote_port)
    conn = None
    for i in range(0,4):
        try:
            conn = open_connection(remote_ip, remote_port)
            info("Connected to Bob")
            break
        except ConnectionRefusedError as e:
            info("Unable to connect to %s:%d, will try again shortly" % (remote_ip, remote_port))
            sleep(15)
    if conn == None:
        raise Exception("Unable to connect to peer")
    return conn

def recv_key_from_lan(conn, other_scan_payload):
    """
    :param conn: Connection to peer
    :type conn: :class:`Socket`
    :param other_scan_payload: decoded contents of the peer's QR code
    :type other_scan_payload: list
    :returns: public key
    :rtype: binary string
    """
    record = recv_record(conn)
    if record[1] == RECORD_TYPE_KEY:
        pub = record[2]
        # If the key doesn't match the commitment, we must abort
        if other_scan_payload[1] != create_commitment(pub):
            send_record(conn, RECORD_TYPE_ABORT, b"")
            raise Exception("Public key did not match commitment!")
    else:
        raise Exception("Unexpected record type received: {}".format(record[1]))
    return pub

def establish_master_key(my_qr_payload, peer_qr_payload, priv, pub, s):
    """
    Takes the QR payload wiht our commitment and the QR payload with our peer's
    commitment and does a key exchange using BQP to derive a master key.

    :param my_qr_payload: The decoded version of our qr payload
    :type my_qr_payload: list
    :param peer_qr_payload: The decoded version of the peer's qr payload
    :type peer_qr_payload: list
    :param priv: Our ephemeral private key
    :type priv: :class:`py:SigningKey`
    :param pub: Our ephemeral public key
    :type pub: :class:`py:VerifyingKey`
    :param s: Socket that we are listening on
    :type s: :class:`py:Socket`
    :returns: shared secret (master_key) and an indicator if this peer was alice
    :rtype: two element tuple of bytes and bool
    """
    my_encoded_payload = encode_data(my_qr_payload)
    peer_encoded_payload = encode_data(peer_qr_payload)

    # Per section 3 of the BQP spec, we determine whether we are ALICE or BOB
    i_am_alice = my_qr_payload[1] < peer_qr_payload[1]
    info("I am %s" % ("Bob", "Alice")[i_am_alice])

    # The next phase of the key exchange is done online, which is described in
    # section 4 of the BQP spec
    if i_am_alice:
        s.close()  # Close my connection, I want to use Bob's connection
        conn = connect_to_peer(peer_qr_payload)
        send_record(conn, RECORD_TYPE_KEY, pub.to_bytes())
        pub_b = recv_key_from_lan(conn, peer_qr_payload)
        shared_secret = calculate_shared_secret_alice(priv, pub.to_bytes(), pub_b)
        debug("shared secret = %s" % shared_secret)
        # Alice sends her confirmation code, and then receives and checks Bob's
        send_record(conn,
                    RECORD_TYPE_CONFIRM,
                    gen_confirmation_alice(shared_secret,
                                           my_encoded_payload,
                                           pub.to_bytes(),
                                           peer_encoded_payload,
                                           pub_b)
                   )
        record = recv_record(conn)
        if record[1] == RECORD_TYPE_CONFIRM:
            generated_confirmation = gen_confirmation_bob(shared_secret,
                                                          my_encoded_payload,
                                                          pub.to_bytes(),
                                                          peer_encoded_payload,
                                                          pub_b)
            if record[2] != generated_confirmation:
                send_record(conn, RECORD_TYPE_ABORT, b"")
                raise Exception("Confirmation record did not match expeced value!")
        pub_b = None  # We're done with Bob's public key, so we forget it now
    else:
        debug("Waiting for Alice to connect to us...")
        conn, remote_addr = s.accept()
        pub_a = recv_key_from_lan(conn, peer_qr_payload)
        send_record(conn, RECORD_TYPE_KEY, pub.to_bytes())
        shared_secret = calculate_shared_secret_bob(priv, pub_a, pub.to_bytes())
        debug("shared secret = %s" % shared_secret)
        # Bob receives Alice's confirmation, verifies it, then sends his own
        record = recv_record(conn)
        if record[1] == RECORD_TYPE_CONFIRM:
            generated_confirmation = gen_confirmation_alice(shared_secret,
                                                            peer_encoded_payload,
                                                            pub_a,
                                                            my_encoded_payload,
                                                            pub.to_bytes())
            if record[2] != generated_confirmation:
                send_record(conn, RECORD_TYPE_ABORT, b"")
                raise Exception("Confirmation record did not match expeced value!")
        send_record(conn,
                    RECORD_TYPE_CONFIRM,
                    gen_confirmation_bob(shared_secret,
                                         peer_encoded_payload,
                                         pub_a,
                                         my_encoded_payload,
                                         pub.to_bytes()))
        pub_a = None  # We're done with Alice's public key, so we forget it now
    conn.close()
    return KDF(shared_secret, [MASTER_KEY]), i_am_alice
