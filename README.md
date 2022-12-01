This is a hacked together Python implementation of the Briar specification.
Briar spec: https://code.briarproject.org/akwizgran/briar-spec

It should work anywhere, but it has only tested with Python on Linux.  Not
tested with legacy Python (Python2).

This package has not gone through any formal, independent testing for
compatibility nor security.  Use at your own risk.

# Exchanging Contacts (Bramble QR Code Protocol)
The `exchange_contacts.py` script demonstrates how to use the Bramble QR Code
Protocol (BQP) to establish a shared master key.

This process does not require any existing keys. Ephemeral keys are generated
and used. To ensure the keys are not intercepted, a QR code is generated that
is used to provide an assurance that the key received over the network is the
one that was expected.

As this is a command line script which is intended to be able to be run on
systems where these is no camera, the base64 encoded payload that would be put
in the QR code is printed on the screen so it can be copied and pasted into the
other peer's terminal. A QR code is also written (`contact_exchange.png` by
default) to test scanning the QR code if desired.

```sh
# Make a directory for each peer
mkdir peer1
mkdir peer2

# In one terminal
cd peer1
../exchange_contacts.py -vv -l "127.0.0.1:9999"
# copy the base64 data you see

# In another terminal
cd peer2
../exchange_contacts.py -vv -l "127.0.0.1:9998"
# enter your peer's base64 data
# copy the base64 data you see and enter it on the first terminal

# If it worked correctly, you should have a master.key and role file in your
# current working directory for each peer. The keys should match.

# This can be done on two different computers by just updating the IP address to
# be your network accessible IP address.
```

If anything goes wrong, you can just start over.

If you want to see the data, feed the base64 data into `parse_qr_data1.py` or
`decode_data.py`.


# Bramble Transport Protocol
TODO

# Bramble Synchronization Protocol
TODO
