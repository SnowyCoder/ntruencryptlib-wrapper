import unittest
import ntruencrypt

EXAMPLE_DATA = b"Nel mezzo del cammin di nostra vita mi ritrovai per una selva oscura, che' la diritta via era smarita"


class NtruTest(unittest.TestCase):
    def test_simple_usage(self):
        # KeyPair generation
        key_pair = ntruencrypt.create_keys()

        # First assignment
        pub_key = key_pair.public_key
        prv_key = key_pair.private_key

        # Second assignment (equal to the first one)
        pub_key, prv_key = key_pair

        # Check public key binary coding
        deriv_key = ntruencrypt.PublicKey.from_binary(pub_key.as_binary)
        self.assertEqual(deriv_key.as_binary, pub_key.as_binary)  # Check key decomposition
        self.assertEqual(deriv_key.params, pub_key.params)  # Check parameter recomposition

        # Check private key binary coding
        deriv_key = ntruencrypt.PublicKey.from_binary(prv_key.as_binary)
        self.assertEqual(deriv_key.as_binary, prv_key.as_binary)  # Check key decomposition
        self.assertEqual(deriv_key.params, prv_key.params)  # Check parameter recomposition

        # Check encryption
        encrypted_data = pub_key.encrypt(EXAMPLE_DATA)
        self.assertNotEqual(encrypted_data, EXAMPLE_DATA)
        # Check decryption
        decrypted_data = prv_key.decrypt(encrypted_data)
        self.assertEqual(decrypted_data, EXAMPLE_DATA)

    def check_with_params(self, params: ntruencrypt.EncryptionParameter, message: bytes):
        # KeyPair generation
        key_pair = ntruencrypt.create_keys(params)

        # Keys from KeyPair
        pub_key, prv_key = key_pair

        self.assertEqual(pub_key.max_message_len, params.max_msg_len)

        # Check encryption/decryption
        encrypted_data = pub_key.encrypt(message)
        decrypted_data = prv_key.decrypt(encrypted_data)
        self.assertEqual(decrypted_data, message)

    def test_all_params(self):
        for key_type in ntruencrypt.KeyType:
            for key_size in ntruencrypt.possible_key_sizes:
                params = ntruencrypt.get_parameter(key_type, key_size)

                # Check message length
                message = EXAMPLE_DATA
                if len(message) > params.max_msg_len:
                    # Adapt length to parameter's maximum length
                    message = message[:params.max_msg_len]

                self.check_with_params(params, message)

    def test_der_conversion(self):
        key_pair = ntruencrypt.create_keys()
        original_key = key_pair.public_key

        der_data = key_pair.public_key.to_der()
        computed_key = ntruencrypt.PublicKey.from_der(der_data)

        self.assertEqual(original_key.as_binary, computed_key.as_binary)

    def test_custom_drbg(self):
        drbg = ntruencrypt.Drbg()
        key_pair = drbg.create_keys()
        pub_key, prv_key = key_pair

        enc_data = pub_key.encrypt(EXAMPLE_DATA, drbg=drbg)
        org_data = prv_key.decrypt(enc_data)
        self.assertEqual(org_data, EXAMPLE_DATA)

    def test_invalid_keysize(self):
        # key_size not possible
        self.assertRaises(ValueError, ntruencrypt.get_parameter, key_size=123)

    def test_message_too_long(self):
        pub_key, prv_key = ntruencrypt.create_keys()
        message_size = pub_key.max_message_len + 1
        data = b'?' * message_size
        self.assertRaises(ValueError, pub_key.encrypt, data)

    def test_wrong_parameter_type(self):
        pub_key, prv_key = ntruencrypt.create_keys()
        # The only convertible type is bytes, every type convertion falls out of the scope of this library
        self.assertRaises(ValueError, pub_key.encrypt, "Non bytes string")  # Non-bytes string (notice missing b prefix)
        self.assertRaises(ValueError, pub_key.encrypt, 42)                  # Random int
        self.assertRaises(ValueError, pub_key.encrypt, (b'First', 42))      # Any other non-bytes thing


if __name__ == '__main__':
    unittest.main()
