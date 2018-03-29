#!/usr/bin/env python3
from argparse import ArgumentParser
from bdf import encode_data
from bqp import TRANSPORT_ID_BLUETOOTH, TRANSPORT_ID_LAN
from log_helper import setup_logging
from sys import stdout

if __name__ == "__main__":
    parser = ArgumentParser(description='Decodes one item from a stream and displays it')
    group = parser.add_mutually_exclusive_group()
    group.add_argument("-v", "--verbose", action="count", help=('Verbose output (for debugging issues)'))
    group.add_argument("-q", "--quiet", action="count", help=('Quiet down the output'))
    args = parser.parse_args()

    setup_logging(args)

    protocol_version = 2
    pk_commitment = b'\x12\xdb>\xbc;\x84\xbeQ\xd0?g\xab]m\xb7P'
    transport = TRANSPORT_ID_LAN
    data = encode_data([protocol_version, pk_commitment, [transport, b'\xbcv^X`\x82']])
    stdout.buffer.write(data)
