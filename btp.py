#!/usr/bin/env python3
# Python implementation of the Briar Transport Protocol
from constants import TRANSPORT_ID_STRING_LAN
from cryptography.hazmat.primitives import poly1305
from struct import pack
from time import time
try:
    from pure_salsa20 import xsalsa20_xor as ENC
    from pure_salsa20 import xsalsa20_xor as DEC
    from secrets import token_bytes as R
    from blake256.blake256 import blake_hash as H # Blake2 wasn't added to hashlib in Python 3.4.3
except ImportError as e:
    print("%s" % e)
    print("To install dependencies: pip3 install pure_salsa20 blake256")
    from sys import exit
    exit(1)

# Version of the BTP that we are following and constants for that version
PROTOCOL_VERSION = 4;
KEY_LEN = 32
NONCE_LEN = 24
AUTH_LEN = 16

# Maximum difference in the peer's clocks
D = 86400 # 1 day
# Maximum transport latency for TCP
TCP_L = 60    # 1 minute


ALICE_HANDSHAKE_TAG_KEY = b"org.briarproject.bramble.transport/ALICE_HANDSHAKE_TAG_KEY"
ALICE_HANDSHAKE_HEADER_KEY = b"org.briarproject.bramble.transport/ALICE_HANDSHAKE_HEADER_KEY"
BOB_HANDSHAKE_TAG_KEY = b"org.briarproject.bramble.transport/BOB_HANDSHAKE_TAG_KEY"
BOB_HANDSHAKE_HEADER_KEY = b"org.briarproject.bramble.transport/BOB_HANDSHAKE_HEADER_KEY"
ROTATE = b"org.briarproject.bramble.transport/ROTATE"

def PRF(k, m):
    """
    Pseudorandom function (PRF) implemented as defined in section 2.2 of the BTP
    specification.

    :param k: Secret key
    :type k: bytes
    :param m: Message
    :type m: bytes
    :returns: pseudo-random, but deterministic, bytes
    :rtype: bytes
    """
    return H(k + m)

def KDF(k, m):
    """
    Key derivation function (KDF) implemented as defined in section 2.2 of the
    specification.

    :param k: Secret key
    :type k: bytes
    :param m: Messages
    :type m: list
    :returns: key material
    :rtype: bytes
    """
    total_message = b""
    for i in m:
        total_message += pack(">I", len(i)) + i
    return PRF(k, total_message)

def initial_keys(root_key, transport_id, i_am_alice):
    """
    Implements initial key derivation for rotational mode, as described in
    section 2.4 of the spec. These should be considered to be the key of the
    previous timeperiod (P-1). They can be rotated once to obtain the keys for
    the current time period. After the initial keys are established, the root
    key must be discarded.

    :param root_key: Root key
    :type root_key: bytes
    :param transport_id: a string identifying which transport to use
    :type transport_id: binary string
    :param i_am_alice: Flag indicating if the caller's role is of Alice
    :type i_am_alice: bool
    :returns: Tuple of keys: outgoing tag, outgoing header, incoming tag,
              incoming header
    :rtype: 4 element tuple, all elements are bytes
    """
    if i_am_alice:
        outgoing_tag_key = KDF(root_key, [ALICE_HANDSHAKE_TAG_KEY, transport_id])
        outgoing_header_key = KDF(root_key, [ALICE_HANDSHAKE_HEADER_KEY, transport_id])
        incoming_tag_key = KDF(root_key, [BOB_HANDSHAKE_TAG_KEY, transport_id])
        incoming_header_key = KDF(root_key, [BOB_HANDSHAKE_HEADER_KEY, transport_id])
    else:
        outgoing_tag_key = KDF(root_key, [BOB_HANDSHAKE_TAG_KEY, transport_id])
        outgoing_header_key = KDF(root_key, [BOB_HANDSHAKE_HEADER_KEY, transport_id])
        incoming_tag_key = KDF(root_key, [ALICE_HANDSHAKE_TAG_KEY, transport_id])
        incoming_header_key = KDF(root_key, [ALICE_HANDSHAKE_HEADER_KEY, transport_id])

    return outgoing_tag_key, outgoing_header_key, incoming_tag_key, incoming_header_key

def get_time_period(transport_id, t=None):
    """
    Returns the current timeperiod for the given transport.

    :param transport_id: The transport ID
    :type transport_id: binary string
    :param t: unix timestamp
    :type t: int
    :returns: The timeperiod we are currently in
    :rtype: int
    """
    timestamp = time() if t == None else t
    if transport_id == TRANSPORT_ID_STRING_LAN:
        return int(timestamp/(D+TCP_L))
    raise NotImplemented("Transport %s is not yet implemented" % transport_id.decode())

def rotate_keys(otk, ohk, itk, ihk, P):
    """
    Rotates the keys to obtain the keys for the next timeperiod. The caller
    should discart old keys as soon as they are no longer needed.

    :param otk: Outgoing tag key
    :type otk: bytes
    :param ohk: Outgoing header key
    :type ohk: bytes
    :param itk: Incoming tag key
    :type itk: bytes
    :param ihk: Incoming header key
    :type ihk: bytes
    :param P: Time period for which we are establishing keys
    :type P: int
    :returns: Tuple of keys: outgoing tag, outgoing header, incoming tag,
              incoming header
    :rtype: 4 element tuple, all elements are bytes
    """
    outgoing_tag_key = KDF(otk, [ROTATE, pack(">Q", P)])
    outgoing_header_key = KDF(ohk, [ROTATE, pack(">Q", P)])
    incoming_tag_key = KDF(itk, [ROTATE, pack(">Q", P)])
    incoming_header_key = KDF(ihk, [ROTATE, pack(">Q", P)])

    return outgoing_tag_key, outgoing_header_key, incoming_tag_key, incoming_header_key 

def handshake_mode(root_key, P, transport_id, i_am_alice):
    """
    Implements handshake mode, as described in section 2.5 of the spec.

    :param root_key: Root key
    :type root_key: bytes
    :param P: Time period for which we are establishing keys
    :type P: int
    :param transport_id: a string identifying which transport to use
    :type transport_id: binary string
    :param i_am_alice: Flag indicating if the caller's role is of Alice
    :type i_am_alice: bool
    :returns: Tuple of keys: outgoing tag, outgoing header, incoming tag,
              incoming header
    :rtype: 4 element tuple, all elements are bytes
    """
    if i_am_alice:
        outgoing_tag_key = KDF(root_key, [ALICE_HANDSHAKE_TAG_KEY, transport_id, pack(">Q", P)])
        outgoing_header_key = KDF(root_key, [ALICE_HANDSHAKE_HEADER_KEY, transport_id, pack(">Q", P)])
        incoming_tag_key = KDF(root_key, [BOB_HANDSHAKE_TAG_KEY, transport_id, pack(">Q", P)])
        incoming_header_key = KDF(root_key, [BOB_HANDSHAKE_HEADER_KEY, transport_id, pack(">Q", P)])
    else:
        outgoing_tag_key = KDF(root_key, [BOB_HANDSHAKE_TAG_KEY, transport_id, pack(">Q", P)])
        outgoing_header_key = KDF(root_key, [BOB_HANDSHAKE_HEADER_KEY, transport_id, pack(">Q", P)])
        incoming_tag_key = KDF(root_key, [ALICE_HANDSHAKE_TAG_KEY, transport_id, pack(">Q", P)])
        incoming_header_key = KDF(root_key, [ALICE_HANDSHAKE_HEADER_KEY, transport_id, pack(">Q", P)])

    return outgoing_tag_key, outgoing_header_key, incoming_tag_key, incoming_header_key
