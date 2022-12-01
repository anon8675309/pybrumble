#!/usr/bin/env python3
"""
This program will generate an ephemeral keypair, as described in section 2 of
the BQP specification in order to get a shared secret key.

Example usage:
./exchange_contacts.py -l 127.0.0.1:9999
"""
from argparse import ArgumentParser
from base64 import b64encode, b64decode
from bdf import encode_data, extract_data, bind_to_lan, open_connection, \
        recv_record, send_record
from binascii import hexlify
from bqp import KDF, obtain_wifi_info, calculate_shared_secret_alice, \
        calculate_shared_secret_bob, gen_keypair, create_commitment, \
        gen_scan_payload, gen_confirmation_alice, gen_confirmation_bob, \
        read_keys, save_keys
from constants import RECORD_TYPE_KEY, RECORD_TYPE_CONFIRM, RECORD_TYPE_ABORT, \
                      MASTER_KEY
from log_helper import setup_logging
from logging import debug, info, error, basicConfig, INFO, DEBUG
from sys import stdin
from time import sleep

try:
    from pyqrcode import create
    import png  # Used by pyqrcode to output image
except ImportError as e:
    info("%s" % e)
    info("To install dependencies: pip3 install pure25519 blake256 pyqrcode pypng")
    from sys import exit
    exit(1)


DEFAULT_QR_CODE_FILENAME="contact_exchange.png"
DEFAULT_PRIVATE_KEY_FILE="ephemeral"
DEFAULT_PUBLIC_KEY_FILE="ephemeral.pub"

def get_arg_parser():
    """
    Builds program arguments.
    :returns: Parser which will deal with command line arguments
    :rtype: :class:`ArgumentParser`
    """
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
    return parser

def write_barcode(commitment, bluetooth, lan):
    """
    Creates a QR code to be scanned from a public key and transport types.
    :param commitment: commitment for my peer to verify the keys are correct
    :type commitment: binary string
    :param bluetooth: true if Bluetooth is an available transport
    :type bluetooth: boolean
    :param lan: true if LAN is an available transport
    :type lan: boolean
    :returns: BDF encooded payload, QR code that the other peer should scan
    :rtype: two element tuple of: bytes and :class:`QRCode` object
    """
    payload_data = gen_scan_payload(commitment, bluetooth, lan)
    debug("payload_data = %s" % repr(payload_data))
    my_scan_payload = encode_data(payload_data)
    b64_encoded_payload = b64encode(my_scan_payload)

    info("qr code payload = %s" % b64_encoded_payload.decode())
    return (my_scan_payload, create(b64_encoded_payload))

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


if __name__ == "__main__":
    parser = get_arg_parser()
    args = parser.parse_args()
    setup_logging(args)

    priv, pub = gen_keypair()  # 2.1 key generation
    commitment = create_commitment(pub.to_bytes())

    # QR code scan payload
    wire_encoded_payload, qrcode = write_barcode(commitment, args.bluetooth, args.lan)
    qrcode.png(args.output, scale=8)

    # Read in the other person's scan_payload from stdin
    binary_other_scan_payload = b64decode(stdin.readline())
    other_scan_payload, reamining_data = extract_data(binary_other_scan_payload)
    debug("peer's QR scan payload = %s" % repr(other_scan_payload))

    # Now we need to make sure we're bound on the IP/port we said we'd be listening on
    ip, port = args.lan.split(":")
    s = bind_to_lan(ip, port)

    # Per section 3 of the bqp spec, we determine whether we are ALICE or BOB
    i_am_alice = commitment < other_scan_payload[1]
    info("I am %s" % ("Bob", "Alice")[i_am_alice])
    # The next phase of the key exchange is done online, which is described in section 4 of the bqp spec
    if i_am_alice:
        s.close()  # Close my connection, I want to use Bob's connection
        conn = connect_to_peer(other_scan_payload)
        send_record(conn, RECORD_TYPE_KEY, pub.to_bytes())
        pub_b = recv_key_from_lan(conn, other_scan_payload)
        shared_secret = calculate_shared_secret_alice(priv, pub.to_bytes(), pub_b)
        debug("shared secret = %s" % shared_secret)
        # Alice sends her confirmation code, and then receives and checks Bob's
        send_record(conn,
                    RECORD_TYPE_CONFIRM,
                    gen_confirmation_alice(shared_secret,
                                           wire_encoded_payload,
                                           pub.to_bytes(),
                                           binary_other_scan_payload,
                                           pub_b)
                   )
        record = recv_record(conn)
        if record[1] == RECORD_TYPE_CONFIRM:
            generated_confirmation = gen_confirmation_bob(shared_secret,
                                                          wire_encoded_payload,
                                                          pub.to_bytes(),
                                                          binary_other_scan_payload,
                                                          pub_b)
            if record[2] != generated_confirmation:
                send_record(conn, RECORD_TYPE_ABORT, b"")
                raise Exception("Confirmation record did not match expeced value!")
    else:
        debug("Waiting for Alice to connect to us on port %s..." % port)
        conn, remote_addr = s.accept()
        pub_a = recv_key_from_lan(conn, other_scan_payload)
        send_record(conn, RECORD_TYPE_KEY, pub.to_bytes())
        shared_secret = calculate_shared_secret_bob(priv, pub_a, pub.to_bytes())
        debug("shared secret = %s" % shared_secret)
        # Bob receives Alice's confirmation, verifies it, then sends his own
        record = recv_record(conn)
        if record[1] == RECORD_TYPE_CONFIRM:
            generated_confirmation = gen_confirmation_alice(shared_secret,
                                                            binary_other_scan_payload,
                                                            pub_a,
                                                            wire_encoded_payload,
                                                            pub.to_bytes())
            if record[2] != generated_confirmation:
                send_record(conn, RECORD_TYPE_ABORT, b"")
                raise Exception("Confirmation record did not match expeced value!")
        send_record(conn,
                    RECORD_TYPE_CONFIRM,
                    gen_confirmation_bob(shared_secret,
                                         binary_other_scan_payload,
                                         pub_a,
                                         wire_encoded_payload,
                                         pub.to_bytes()))
        pub_a = None  # We're done with Alice's public key, so we forget it now
    master_key = KDF(shared_secret, [MASTER_KEY])

    # Forget things so shared secret can not be re-derived
    shared_secret = None    # forget the shared secret
    priv, pub = None, None  # forget our ephemeral keys too
    commitment = None       # and our commitment too

    with open("master.key", "wb") as f:
        f.write(master_key)
        info("master.key written to disk for the next step")
    with open("role", "w") as f:
        f.write(("bob\n", "alice\n")[i_am_alice])
        info("role written to disk for the next step")
