This is a hacked together Python implementation of the Briar specification.
Briar spec: https://code.briarproject.org/akwizgran/briar-spec

It should work anywhere, but it has only tested with Python on Linux.  Not
tested with legacy Python (Python2).

This package has not gone through any formal, independent testing for
compatibility nor security.  Use at your own risk.

# Exchanging Contacts (Bramble QR Code Protocol)
There's a file called exchange_contacts.py which does some weird stuff, such as
saving ephemerial keys.  Why would anyone store something which is meant to be
ephemerial?  How is this even useful?  Allow me to explain.

The easiest way to explain is by example.  First, let us make some directories
for some identities, and then we'll do a key exchange over the LAN.

```
mkdir peer1
mkdir peer2
```

Now, we go into peer1 and generate a keypair.

```
cd peer1
../exchange_contacts.py -vv -l "10.137.2.36:9999"
```

This generates a keypair, creates an encoded scan payload and prints it out in
base64.  This is what we're going to feed the other peer, so it knows what key
to expcet and where to get it.  If you want to see the data, feed the base64
data into parse_qr_data1.py or decode_data.py.

Next, we take that scan payload, and feed it into the second peer.  The second
peer will generate its own scan payload which we will need to feed back into
the first peer.  In another terminal, run this....

```
cd peer2
echo YCECURAWh+Q+kAU4MV0qJ8WZT0dIYCEBUQQKiQIkIicPgIA= | ../exchange_contacts.py -vv -l "10.137.2.36:9998"
# The base64 data came from the "peer1" terminial
```

If peer2 says "I am Bob", it means it's waiting for Alice (peer1) to connect.
In this case, we can paste in peer2's scan payload and paste it into peer1's
terminal (who has been waiting for data on stdin).  It will then perform the
key exchange to get the shared secret.

If anything went wrong, you can just start over and the same keys will be used.
This is why the keys were saved, to make it easy.  The point of this is just to
demonstrate how the system would work.

## Section 4.3 Eratta
confirm_a and confirm_b both use keyed MACs and the key is "CONFIRMATION_MAC".
The "CONFIRMATION_KEY" can be seen on line 35, and the "CONFIRMATION_MAC" on line 49 of:
./bramble-core/src/main/java/org/briarproject/bramble/crypto/KeyAgreementCryptoImpl.java

# Bramble Transport Protocol
TODO

# Bramble Synchronization Protocol
TODO

