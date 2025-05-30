from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import logging
logger = logging.getLogger(__name__.split('.')[0])

RSA_PUBLIC_KEY = b'-----BEGIN PUBLIC KEY-----\nMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA11148jvq4hccqzbxMFFm\nPkMxBPiC0ILhjYnm782HqxJQU6TBSZTnVlCPzjOiTKFa/L8z5HpxWbd6yLjF2wJo\npV5FQIJJnej6L1nbow8FNg3a2F+RXaKQMGISr0xrZrYqyE1jmZP1dmzGFV19lTu1\nQCeUh1EGkkVexYHD/Nfc7xXMYRy7HII2lNJFfmwIoup5uPfT5BDIc2esb7ol+hIX\n8EFP31r9kNqejQ0OR+BFTKiWV/Ep02nO3TvZUn65tAZQD3YVM4Yr1OTc7XzBwmgw\nAFlynldawI7K5MU2OM9H5eVK5BoiA6XsLjfB+fIsksEyaJ5Ek20hZPsFjvP+Zwd4\nD8/Q3CWMDu2NGcYL6dkY6xq8TEW9WTAUAT67d2DmZz5dIQbALzWeUKWE4HZwlTOp\na2QPrRNi9ujJXGtBuKpTCoJ1zzBOwY/j99rXLAVqxe/RnxETpU+t5Cd+Y6XGzyax\nlmw1zzBiiiZunD+X7lYhH27lQSBZAnAyy+FPNp0U0fSaFHi310FByXyGWJwQxDZA\nc8z1g0JW7feMAaYRtPpMDuj/gnAA3PqXDjsOzqMDXdIF6+DeBy/ltvGwl6G96/g5\nRtqOXeAhxJC6s7EXGM1SKFcmMVZdgwzA6dmAjp1XZE4OqVLubsMzxU6WGQGJTVKz\n4CJhPGa8vOoOzm2NOJHgAw8CAwEAAQ==\n-----END PUBLIC KEY-----'
class SignLic:
    """
    A class to handle signing and verifying data using RSA.
    """
    def __init__(self, rsa_public_key=RSA_PUBLIC_KEY, rsa_private_key=None):
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
        ret = True
        verifier = pkcs1_15.new(RSA.import_key(self.rsa_public_key))
        try:
            verifier.verify(SHA256.new(data), signature)
        except (ValueError, TypeError):
            logger.error("RSA signature verification failed!")
            ret = False
        return ret


    def rsa_sign_data(self, data):
        signer = pkcs1_15.new(RSA.import_key(self.rsa_private_key))
        signature = signer.sign(SHA256.new(data))
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
