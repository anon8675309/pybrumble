#!/usr/bin/env python3
"""
This program will generate an ephemeral keypair, as described in section 2 of
the BQP specification in order to get a shared secret key.

Example usage:
./exchange_contacts.py -l 127.0.0.1:9999
"""
from argparse import ArgumentParser
from base64 import b64encode, b64decode
from bdf import encode_data, extract_data, bind_to_lan
from bqp import gen_keypair, create_commitment, gen_scan_payload, \
                establish_master_key
from log_helper import setup_logging
from logging import debug, info, error, basicConfig, INFO, DEBUG
from sys import stdin

try:
    from pyqrcode import create
    import png  # Used by pyqrcode to output image
except ImportError as e:
    info("%s" % e)
    info("To install dependencies: pip3 install pure25519 blake256 pyqrcode pypng")
    from sys import exit
    exit(1)


DEFAULT_QR_CODE_FILENAME="contact_exchange.png"

def get_arg_parser():
    """
    Builds program arguments.

    :returns: Parser which will deal with command line arguments
    :rtype: :class:`ArgumentParser`
    """
    parser = ArgumentParser(description='Generates ephemerial keys (if they do not exist) and does a key exchange')
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
    :returns: decooded payload, QR code that the other peer should scan
    :rtype: two element tuple of: bytes and :class:`QRCode` object
    """
    payload_data = gen_scan_payload(commitment, bluetooth, lan)
    debug("payload_data = %s" % repr(payload_data))
    my_scan_payload = encode_data(payload_data)
    b64_encoded_payload = b64encode(my_scan_payload)

    info("qr code payload = %s" % b64_encoded_payload.decode())
    return (payload_data, create(b64_encoded_payload))

if __name__ == "__main__":
    parser = get_arg_parser()
    args = parser.parse_args()
    setup_logging(args)

    priv, pub = gen_keypair()  # 2.1 key generation
    commitment = create_commitment(pub.to_bytes())

    # QR code scan payload
    my_scan_payload, qrcode = write_barcode(commitment, args.bluetooth, args.lan)
    wire_encoded_payload = encode_data(my_scan_payload)
    qrcode.png(args.output, scale=8)

    # Read in the other person's scan_payload from stdin
    binary_other_scan_payload = b64decode(stdin.readline())
    other_scan_payload, reamining_data = extract_data(binary_other_scan_payload)
    debug("peer's QR scan payload = %s" % repr(other_scan_payload))

    # Now we need to make sure we're bound on the IP/port we said we'd be listening on
    ip, port = args.lan.split(":")
    s = bind_to_lan(ip, port)

    # Do exchange to get the master_key and what our role was in the protocol
    master_key, i_am_alice = establish_master_key(my_scan_payload,
                                                  other_scan_payload,
                                                  priv, pub, s)

    # Forget things so shared secret can not be re-derived
    priv, pub = None, None  # forget our ephemeral keys too
    commitment = None       # and our commitment too

    with open("master.key", "wb") as f:
        f.write(master_key)
        info("master.key written to disk for the next step")
    with open("role", "w") as f:
        f.write(("bob\n", "alice\n")[i_am_alice])
        info("role written to disk for the next step")
