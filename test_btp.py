#!/usr/bin/env python3
from unittest import TestCase, main
from btp import PRF, KDF, initial_keys, get_time_period, rotate_keys, \
                handshake_mode, KEY_LEN, NONCE_LEN, AUTH_LEN, D, TCP_L, \
                calculate_tag, ENC, DEC
from constants import TRANSPORT_ID_STRING_LAN

class BtpTester(TestCase):
    def test_PRF_1(self):
        expected = b'\xb7\xab\x8d\xe7\x06\xe4q\xa9\xdc=\xf5\xcd\toj\xb8\xff\x83\xa1\xc2M_$\x1d\x10\x13\xa5\x94\x1c\x81\x16\x0c'
        result = PRF(b"\x00"*KEY_LEN, b"Hello World!")
        self.assertEqual(result, expected)

    def test_PRF_2(self):
        expected = b'\x9c\xcf\x92\x98c\x9f\x84\x1f\x0bP+\xce\x0f\xa7\xb9\xac\xd9\xe3\x1b\xe5\x9f\xbax3]5\xe9D|\xd2\xc1a'
        result = PRF(b"\xFF"*KEY_LEN, b"Hello World!")
        self.assertEqual(result, expected)

    def test_KDF_1(self):
        expected = b"\xbf\xa7w\xe5\xf3/\xe3\x10\xe3\xc0\xf5\xf4I\x18L\x1fb\x94^.M7\x11\xd0'\xfa\x8c\xee\x0c5\x8b2"
        result = KDF(b"\x00"*KEY_LEN, [b"Hello", b" ", b"World!"])
        self.assertEqual(result, expected)

    def test_initial_keys_match(self):
        a_otk, a_ohk, a_itk, a_ihk = initial_keys(b"\x00"*KEY_LEN, TRANSPORT_ID_STRING_LAN, True)
        b_otk, b_ohk, b_itk, b_ihk = initial_keys(b"\x00"*KEY_LEN, TRANSPORT_ID_STRING_LAN, False)
        self.assertEqual(a_otk, b_itk)
        self.assertEqual(a_ohk, b_ihk)
        self.assertEqual(a_itk, b_otk)
        self.assertEqual(a_ihk, b_ohk)

    def test_initial_keys_1(self):
        expected_otk = b'\xdd\xedo\xcd4\xa9\xc7#9\x85\x02f\xe5\xce\x9aw\xc8s\xc4\xd1<(\xb9\x17\xc9\xfa_\xa3j m\x90'
        expected_ohk = b'\xbb\xb8\xf4\xe5L8\t\xc5b\xc8\xdd\xcb\x08v\xd3\xe7\xdd~\xec,\x1f\xbeXj%\xaf\x931\x86\xca\xe6c'
        expected_itk = b'\xde\xde@\xdb\xa1\xb2\xeb|\x8a\x0e\xea\xde|\x90\x94\xc68Z\x17M\x9cgn\xa5\xdeJ SQ\xfa\x8c1'
        expected_ihk = b'2\xbcl\x8a]\xf0E\x06e\xf2\xa4\xd9\xfc\xd1@d\x9c\x97\x93mH;\xbbQLw+\x88\xfd\xd3\xd8\xd4'
        otk, ohk, itk, ihk = initial_keys(b"\x00"*KEY_LEN, TRANSPORT_ID_STRING_LAN, True)
        self.assertEqual(otk, expected_otk)
        self.assertEqual(ohk, expected_ohk)
        self.assertEqual(itk, expected_itk)
        self.assertEqual(ihk, expected_ihk)

    def test_initial_keys_2(self):
        expected_otk = b'\xde\xde@\xdb\xa1\xb2\xeb|\x8a\x0e\xea\xde|\x90\x94\xc68Z\x17M\x9cgn\xa5\xdeJ SQ\xfa\x8c1'
        expected_ohk = b'2\xbcl\x8a]\xf0E\x06e\xf2\xa4\xd9\xfc\xd1@d\x9c\x97\x93mH;\xbbQLw+\x88\xfd\xd3\xd8\xd4'
        expected_itk = b'\xdd\xedo\xcd4\xa9\xc7#9\x85\x02f\xe5\xce\x9aw\xc8s\xc4\xd1<(\xb9\x17\xc9\xfa_\xa3j m\x90'
        expected_ihk = b'\xbb\xb8\xf4\xe5L8\t\xc5b\xc8\xdd\xcb\x08v\xd3\xe7\xdd~\xec,\x1f\xbeXj%\xaf\x931\x86\xca\xe6c'
        otk, ohk, itk, ihk = initial_keys(b"\x00"*KEY_LEN, TRANSPORT_ID_STRING_LAN, False)
        self.assertEqual(otk, expected_otk)
        self.assertEqual(ohk, expected_ohk)
        self.assertEqual(itk, expected_itk)
        self.assertEqual(ihk, expected_ihk)

    def test_get_time_period_match(self):
        result_1 = get_time_period(TRANSPORT_ID_STRING_LAN)
        result_2 = get_time_period(TRANSPORT_ID_STRING_LAN)
        # There is a small chance the second call will be in the next time
        # period. We handle that edge case in this test.
        if result_1 == result_2:
            self.assertEqual(result_1, result_2)
        else:
            self.assertEqual(result_1, result_2-1)

    def test_get_time_period_1(self):
        expected = 0
        result = get_time_period(TRANSPORT_ID_STRING_LAN, t=0)
        self.assertEqual(result, expected)

    def test_get_time_period_2(self):
        expected = 0
        result = get_time_period(TRANSPORT_ID_STRING_LAN, t=D+TCP_L-1)
        self.assertEqual(result, expected)

    def test_get_time_period_3(self):
        expected = 1
        result = get_time_period(TRANSPORT_ID_STRING_LAN, t=D+TCP_L)
        self.assertEqual(result, expected)

    def test_rotate_keys(self):
        old_otk = b'\xde\xde@\xdb\xa1\xb2\xeb|\x8a\x0e\xea\xde|\x90\x94\xc68Z\x17M\x9cgn\xa5\xdeJ SQ\xfa\x8c1'
        old_ohk = b'2\xbcl\x8a]\xf0E\x06e\xf2\xa4\xd9\xfc\xd1@d\x9c\x97\x93mH;\xbbQLw+\x88\xfd\xd3\xd8\xd4'
        old_itk = b'\xdd\xedo\xcd4\xa9\xc7#9\x85\x02f\xe5\xce\x9aw\xc8s\xc4\xd1<(\xb9\x17\xc9\xfa_\xa3j m\x90'
        old_ihk = b'\xbb\xb8\xf4\xe5L8\t\xc5b\xc8\xdd\xcb\x08v\xd3\xe7\xdd~\xec,\x1f\xbeXj%\xaf\x931\x86\xca\xe6c'

        expected_otk = b'\x12\xb9\x81\x81(\x1f\x9d\xf0UUv\xae\xcdv4\xd7^<"\xcaD\xe0/\xf1\x9a\xcctm\xcc \x03e'
        expected_ohk = b'\x1b\xf4\x83gb\xa9\xa5SI\x83M\xa9Q-\x8a\xa8\x1b\xe0\xeeA\xc0:\\RE\xf0X\xf8O\xdb\xfa\x93'
        expected_itk = b'\x96\xf3\x0c\xe6\xf04\xa9\xdc\xf1\xc8\x0cT\xe3\x85\xa2\xfa\xba\xf4\xb9t\xc4\xf9\xbb\x16\x1f\x87\xb9\x8f;\xa8\xf6\xd4'
        expected_ihk = b'7\xce\x84\x04\x12\xd3n\xf1\x9a\xac\xa0VE\x02\x96\xe1\x94\xe3\xc5!1\xc4\x8b\xb4\xa4\xbf\xcb\xb9@T\x06\x96'

        otk, ohk, itk, ihk = rotate_keys(old_otk, old_ohk, old_itk, old_ihk, 31337)
        self.assertEqual(otk, expected_otk)
        self.assertEqual(ohk, expected_ohk)
        self.assertEqual(itk, expected_itk)
        self.assertEqual(ihk, expected_ihk)

    def test_handshake_mode_match(self):
        a_otk, a_ohk, a_itk, a_ihk = handshake_mode(b"\x00"*KEY_LEN, 1, TRANSPORT_ID_STRING_LAN, True)
        b_otk, b_ohk, b_itk, b_ihk = handshake_mode(b"\x00"*KEY_LEN, 1, TRANSPORT_ID_STRING_LAN, False)
        self.assertEqual(a_otk, b_itk)
        self.assertEqual(a_ohk, b_ihk)
        self.assertEqual(a_itk, b_otk)
        self.assertEqual(a_ihk, b_ohk)

    def test_handshake_mode_1_alice(self):
        expected_otk = b'1\x0c\xd35\xd1\x16\xa9\x9dV\x1f\xc0\xfd\xf6k\xf3\x15\xea\xa7\x81\xa2cq5\xd1\xa3AY\xbbW\x83R6'
        expected_ohk = b'\xdb\x92\x07\x05V\x86\x8ceRS\xac\x1a\xf6\x8d\xe1\xaf\xf1\xf6\x00N?!\x1c=P\xe3xr\xe6\x99\xa9\xa4'
        expected_itk = b'\xab*\xee\x13N\xf2\x06\x85k\x8b\x92\x85\xdcF|\x9a\xab\xd0\\q\x13\x06\x08\xf5\xd54\x17\xe3\xee1\xe1y'
        expected_ihk = b'\xea\xd7\xd8^\xc3\xf3\xb3^\xed\x81\xe8\x1e\xab`\xb2\xf8\'\xf3l\xda\x1d\xaf\x9a\xf86\xab"w\xec$1Q'
        otk, ohk, itk, ihk = handshake_mode(b"\x00"*KEY_LEN, 1, TRANSPORT_ID_STRING_LAN, True)
        self.assertEqual(otk, expected_otk)
        self.assertEqual(ohk, expected_ohk)
        self.assertEqual(itk, expected_itk)
        self.assertEqual(ihk, expected_ihk)

    def test_calculate_tag_handshake_mode(self):
        a_otk, a_ohk, a_itk, a_ihk = handshake_mode(b"\x00"*KEY_LEN, 1, TRANSPORT_ID_STRING_LAN, True)
        b_otk, b_ohk, b_itk, b_ihk = handshake_mode(b"\x00"*KEY_LEN, 1, TRANSPORT_ID_STRING_LAN, False)
        a0 = calculate_tag(a_otk, 0)
        b0 = calculate_tag(b_itk, 0)
        a1 = calculate_tag(a_otk, 1)
        b1 = calculate_tag(b_itk, 1)
        self.assertEqual(a0, b0)
        self.assertEqual(a1, b1)

    def test_ENC_DEC(self):
        plaintext = "There's no place like home".encode()
        key = b"\x80"*KEY_LEN
        nonce = b"\x90"*NONCE_LEN
        ciphertext_with_mac = ENC(key, nonce, plaintext)
        result = DEC(key, nonce, ciphertext_with_mac)
        self.assertNotEqual(plaintext, ciphertext_with_mac)
        self.assertEqual(plaintext, result)
        # encrypted with a different key should result in a different ciphertext
        c2 = ENC(b"\x13"*KEY_LEN, nonce, plaintext)
        self.assertNotEqual(ciphertext_with_mac, c2)
        # and using the same key and a different nonce should also be different
        c3 = ENC(key, b"\x37"*NONCE_LEN, plaintext)
        self.assertNotEqual(ciphertext_with_mac, c3)
        # and of course those should be different than each other
        self.assertNotEqual(c2, c3)


if __name__ == "__main__":
    main()
