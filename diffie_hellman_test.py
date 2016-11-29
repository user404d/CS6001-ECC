import unittest
from ecc_impl import ECC
from diffie_hellman import DiffieHellman

class DiffieHellmanTestCase(unittest.TestCase):

	def test_using_p_192(self):
		""" 
		test diffie hellman key agreement using curve P-192 

		takes about 5 seconds to complete due to size of keys
		"""
    
		point_g = (
		    0x188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012, # Gx
		    0x07192b95ffc8da78631011ed6b24cdd573f977a11e794811) # Gy

		curve = ECC(
		    -3, # a
		    0x64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1, # b
		    6277101735386680763835789423207666416083908700390324961279, # p
		    point_g)

		dh = DiffieHellman(curve, point_g)

		private_key1 = 7919
		public_key1 = dh.generate_public_key(private_key1)

		private_key2 = 8387
		public_key2 = dh.generate_public_key(private_key2)

		private_key3 = 10657
		public_key3 = dh.generate_public_key(private_key3)

		secret_pr1_pub2 = dh.secret_key(private_key1, public_key2)
		secret_pr2_pub1 = dh.secret_key(private_key2, public_key1)

		secret_pr1_pub3 = dh.secret_key(private_key1, public_key3)
		secret_pr3_pub1 = dh.secret_key(private_key3, public_key1)

		secret_pr2_pub3 = dh.secret_key(private_key2, public_key3)
		secret_pr3_pub2 = dh.secret_key(private_key3, public_key2)
		
		# Check if each key pair receives the same shared secret key
		self.assertTrue(secret_pr1_pub2 == secret_pr2_pub1)
		self.assertTrue(secret_pr1_pub3 == secret_pr3_pub1)
		self.assertTrue(secret_pr2_pub3 == secret_pr3_pub2)

		# Non-key pairs should not receive the same shared secret key
		self.assertFalse(secret_pr1_pub3 == secret_pr1_pub2)
		self.assertFalse(secret_pr2_pub1 == secret_pr2_pub3)
		self.assertFalse(secret_pr3_pub2 == secret_pr3_pub1)

if __name__ == "__main__":
	unittest.main()
