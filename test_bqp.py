#!/usr/bin/env python3
from bdf import encode_data, gen_record
from bqp import create_commitment, gen_keypair, read_keys, save_keys, \
                calculate_shared_secret_alice, calculate_shared_secret_bob, \
                gen_confirmation_alice, gen_confirmation_bob, \
                gen_scan_payload, encode_data, establish_master_key
from constants import RECORD_TYPE_KEY, RECORD_TYPE_CONFIRM
from socket import socket
from unittest import TestCase, main
from unittest.mock import AsyncMock, MagicMock, Mock, patch

class BqpTester(TestCase):
    def setUp(self):
        self.a_priv, self.a_pub = read_keys("test/alice.priv", "test/alice.pub")
        self.b_priv, self.b_pub = read_keys("test/bob.priv", "test/bob.pub")

    def test_commitment_a(self):
        expected = b'\xa6/{\xe1FBVd\xb3OUC\x16\xa5\xa6\x04'
        result = create_commitment(self.a_pub.to_bytes())
        self.assertEqual(expected, result)

    def test_commitment_b(self):
        expected = b'\xd0\x92\xa3\xa9i\xafG\xcf\x9c\xde\xab\xd2\xf0R\xe6a'
        result = create_commitment(self.b_pub.to_bytes())
        self.assertEqual(expected, result)

    def test_a_shared_secret(self):
        expected = b'!\xad\xe2\xc9\xe3K\xb0}\xcc9\xe7\xdb\x01\xbe?\x92\xa2=Vu\xf7\xe7\x06`\xf7\xa6\xb6\x11\xad\x01\x89\xfc'
        result = calculate_shared_secret_alice(self.a_priv, self.a_pub.to_bytes(), self.b_pub.to_bytes())
        self.assertEqual(expected, result)

    def test_b_shared_secret(self):
        expected = b'!\xad\xe2\xc9\xe3K\xb0}\xcc9\xe7\xdb\x01\xbe?\x92\xa2=Vu\xf7\xe7\x06`\xf7\xa6\xb6\x11\xad\x01\x89\xfc'
        result = calculate_shared_secret_alice(self.a_priv, self.a_pub.to_bytes(), self.b_pub.to_bytes())
        self.assertEqual(expected, result)

    def test_shared_secret(self):
        a_result = calculate_shared_secret_alice(self.a_priv, self.a_pub.to_bytes(), self.b_pub.to_bytes())
        b_result = calculate_shared_secret_bob(self.b_priv, self.a_pub.to_bytes(), self.b_pub.to_bytes())
        self.assertEqual(a_result, b_result)

    def test_gen_confirmation_alice(self):
        # Test case if bob verifying alice's key matches her commitment
        alice_commitment = create_commitment(self.a_pub.to_bytes())
        alice_payload_data = gen_scan_payload(alice_commitment, None, "127.0.0.1:9999")
        alice_encoded_payload = encode_data(alice_payload_data)

        bob_commitment = create_commitment(self.b_pub.to_bytes())
        bob_payload_data = gen_scan_payload(bob_commitment, None, "127.0.0.1:9998")
        bob_encoded_payload = encode_data(bob_payload_data)

        shared_secret = calculate_shared_secret_alice(self.a_priv,
                                                      self.a_pub.to_bytes(),
                                                      self.b_pub.to_bytes())

        alice_confirmation = gen_confirmation_alice(shared_secret,
                                                    alice_encoded_payload,
                                                    self.a_pub.to_bytes(),
                                                    bob_encoded_payload,
                                                    self.b_pub.to_bytes())
        generated_confirmation = gen_confirmation_alice(shared_secret,
                                                        alice_encoded_payload,
                                                        self.a_pub.to_bytes(),
                                                        bob_encoded_payload,
                                                        self.b_pub.to_bytes())

    def test_gen_confirmation_bob(self):
        # Test case if bob verifying alice's key matches her commitment
        alice_commitment = create_commitment(self.a_pub.to_bytes())
        alice_payload_data = gen_scan_payload(alice_commitment, None, "127.0.0.1:9999")
        alice_encoded_payload = encode_data(alice_payload_data)

        bob_commitment = create_commitment(self.b_pub.to_bytes())
        bob_payload_data = gen_scan_payload(bob_commitment, None, "127.0.0.1:9998")
        bob_encoded_payload = encode_data(bob_payload_data)

        shared_secret = calculate_shared_secret_bob(self.a_priv,
                                                    self.a_pub.to_bytes(),
                                                    self.b_pub.to_bytes())

        alice_confirmation = gen_confirmation_bob(shared_secret,
                                                  alice_encoded_payload,
                                                  self.a_pub.to_bytes(),
                                                  bob_encoded_payload,
                                                  self.b_pub.to_bytes())
        generated_confirmation = gen_confirmation_bob(shared_secret,
                                                      alice_encoded_payload,
                                                      self.a_pub.to_bytes(),
                                                      bob_encoded_payload,
                                                      self.b_pub.to_bytes())

        self.assertEqual(alice_confirmation, generated_confirmation)

    def test_establish_master_key(self):
        expected = b"\nZF\xb8\xe1\xf8t\x14\xa6*\xc2\xa7\xea\x19\xfc\xcf\xef\xdf\\'*S\xcc\xc7\xae\xde\xe9R\x8d\xdf\xe1J"
        # Preperation phase
        alice_commitment = create_commitment(self.a_pub.to_bytes())
        alice_payload_data = gen_scan_payload(alice_commitment, None, "127.0.0.1:9999")
        alice_encoded_payload = encode_data(alice_payload_data)
        bob_commitment = create_commitment(self.b_pub.to_bytes())
        bob_payload_data = gen_scan_payload(bob_commitment, None, "127.0.0.1:9998")
        bob_encoded_payload = encode_data(bob_payload_data)

        # prepare Bob's responses
        shared_secret = calculate_shared_secret_alice(self.a_priv,
                                                      self.a_pub.to_bytes(),
                                                      self.b_pub.to_bytes())
        bob_confirmation = gen_confirmation_bob(shared_secret,
                                                alice_encoded_payload,
                                                self.a_pub.to_bytes(),
                                                bob_encoded_payload,
                                                self.b_pub.to_bytes())
        key_record = gen_record(RECORD_TYPE_KEY, self.b_pub.to_bytes())
        confirmation_record = gen_record(RECORD_TYPE_CONFIRM, bob_confirmation)
        with patch.object(socket, "send", return_value=1):
            with patch.object(socket, "recv", side_effect=[key_record[0:4], key_record[4:], confirmation_record[0:4], confirmation_record[4:]]):
                with patch.object(socket, "connect", return_value=socket):
                    # Bob needs to listen on a socket, we'll mock out Bob's responses
                    s = Mock()
                    # Run the process from Alice's perspective
                    s.close.return_value = None  # Alice is just going to close the socket
                    result, role = establish_master_key(alice_payload_data, bob_payload_data,
                                                        self.a_priv, self.a_pub, s)
                    self.assertEqual(result, expected)
                    self.assertEqual(role, True)

        # From Bob's perspective
        mocked_conn = Mock()
        mocked_conn.send.return_value = 1
        key_record = gen_record(RECORD_TYPE_KEY, self.a_pub.to_bytes())
        alice_confirmation = gen_confirmation_alice(shared_secret,
                                                    alice_encoded_payload,
                                                    self.a_pub.to_bytes(),
                                                    bob_encoded_payload,
                                                    self.b_pub.to_bytes())
        confirmation_record = gen_record(RECORD_TYPE_CONFIRM, alice_confirmation)
        mocked_conn.recv.side_effect = [key_record[0:4], key_record[4:], confirmation_record[0:4], confirmation_record[4:]]
        s = Mock()
        s.accept.return_value = (mocked_conn, "127.0.0.1")
        result2, role = establish_master_key(bob_payload_data, alice_payload_data,
                                            self.b_priv, self.b_pub, s)
        self.assertEqual(result2, expected)
        self.assertEqual(role, False)
        # And make sure Alice's master key matches Bob's
        self.assertEqual(result, result2)


if __name__ == "__main__":
    main()
