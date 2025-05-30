# from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import logging
logger = logging.getLogger(__name__.split('.')[0])

class SignLic:
    """
    A class to handle signing and verifying data using RSA.
    """
    def __init__(self, rsa_public_key=None, rsa_private_key=None):
        """
        Initialize the SignLic object.
        """
        self.rsa_public_key = rsa_public_key
        self.rsa_private_key = rsa_private_key


    def rsa_verify_data(self, data, signature):
        """
        RSA verification of data

        Args:
            data (byte-array): The data to be verified
            signature (byte-array): RSA signature

        Returns:
            False: checks failed
            True: checks passed
        """
        ret = False
        try:
            verifier = pkcs1_15.new(RSA.import_key(self.rsa_public_key))
            verifier.verify(SHA256.new(data), signature)
            ret = True
        except (ValueError, TypeError) as e:
            logger.error(f"RSA signature verification failed: {e}")
        return ret


    def rsa_sign_data(self, data):
        """
        RSA signing of data
        Args:
            data (byte-array): The data to be signed
        Returns:
            signature (byte-array): RSA signature of the data
            None: if signing failed
        """
        signature = None
        try:
            signer = pkcs1_15.new(RSA.import_key(self.rsa_private_key))
            signature = signer.sign(SHA256.new(data))
        except (ValueError, TypeError) as e:
            logger.error(f"RSA signing failed: {e}")
        return signature


    @staticmethod
    def generate_rsa_key_pair(private_key_file='private_key.pem', public_key_file='public_key.pem', key_size=2048):
        """
        Generate an RSA key pair and save to files.

        Args:
            private_key_file (str): Path to save the private key.
            public_key_file (str): Path to save the public key.
            key_size (int): RSA key size in bits.
        """
        key = RSA.generate(key_size)
        with open(private_key_file, 'wb') as priv_file:
            priv_file.write(key.export_key('PEM'))
        with open(public_key_file, 'wb') as pub_file:
            pub_file.write(key.publickey().export_key('PEM'))
