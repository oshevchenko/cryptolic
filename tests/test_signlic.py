import unittest
from unittest.mock import Mock
import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))
# from mq4hemc import HemcMessage, HemcMessageDict, HemcTick, getNotifier
import time
from signlic import SignLic

class TestTimeDateInfo(unittest.TestCase):
    def test_key_gen_1(self):

        # Generate RSA key pair
        path_private_key = os.path.join(os.path.dirname(__file__), 'private_key.pem')
        path_public_key = os.path.join(os.path.dirname(__file__), 'public_key.pem')
        if os.path.exists(path_private_key):
            os.remove(path_private_key)
        if os.path.exists(path_public_key):
            os.remove(path_public_key)
        SignLic().generate_rsa_key_pair(private_key_file=path_private_key, 
                                      public_key_file=path_public_key, 
                                      key_size=2048)

        # Check if the keys were generated
        self.assertTrue(os.path.exists(path_private_key), "Private key file was not created.")
        self.assertTrue(os.path.exists(path_public_key), "Public key file was not created.")


        # Read the keys from files
        with open(path_private_key, 'rb') as f:
            private_key = f.read()
        with open(path_public_key, 'rb') as f:
            public_key = f.read()
        signlic = SignLic(rsa_public_key=public_key, rsa_private_key=private_key)

        # Sign data
        data = b'This is a test data.'
        signature = signlic.rsa_sign_data(data)

        # Verify the signature
        verified_data = signlic.rsa_verify_data(data, signature)
        self.assertEqual(verified_data, True, "Data verification failed.")
        # Verify with wrong data
        wrong_data = b'This is a test wrong data'
        verified_data = signlic.rsa_verify_data(wrong_data, signature)
        self.assertEqual(verified_data, False, "Data verification failed.")
    def test_key_gen_2(self):
        signlic = SignLic()

        # Sign data
        data = b'This is a test data.'
        signature = signlic.rsa_sign_data(data)

        # Verify the signature
        verified_data = signlic.rsa_verify_data(data, signature)
        self.assertEqual(verified_data, False, "Data verification failed.")
        # Verify with wrong data
        wrong_data = b'This is a test wrong data'
        verified_data = signlic.rsa_verify_data(wrong_data, signature)
        self.assertEqual(verified_data, False, "Data verification failed.")
if __name__ == "__main__":
    unittest.main()
