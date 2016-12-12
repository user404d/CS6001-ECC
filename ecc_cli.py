#!/usr/bin/python

""" 
Command line interface for ECC and Diffie Hellman 

ECC and Diffie Hellman are
used to generate public keys and shared secret keys.
"""
import json
import os, sys, getopt
from ecc_impl import ECC
from diffie_hellman import DiffieHellman

def main(argv):
   """
   Example example1.json 
   {
    "point_x": "0x188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012",
    "point_y": "0x07192b95ffc8da78631011ed6b24cdd573f977a11e794811",
    "a": "-3",
    "b": "0x64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1",
    "p": "6277101735386680763835789423207666416083908700390324961279",
    "private_key1": "7919",
    "private_key2": "8387"
   }
   """

   filename = "example1.json"

   help_text = 'ecc_cli.py --input <json input file>'

   if len(argv) == 0:
      print(help_text)
      sys.exit(2)

   try:
      opts, args = getopt.getopt(argv,"h:", ["input="])
   except getopt.GetoptError:
      print(help_text)
      sys.exit(2)
   
   # Process input from arguments 
   for opt, arg in opts:
      if opt == '-h':
         print(help_text)
         sys.exit()
      elif opt == ("--input"):
         filename = arg

   if not os.path.isfile(filename):
      print("{} not found.".format(filename))
      sys.exit(2)

   # Process input from json file
   with open(filename) as data_file:    
       data = json.load(data_file)

   point_x = int(data["point_x"], 16)
   point_y = int(data["point_y"], 16)
   a = int(data["a"])
   b = int(data["b"], 16)
   p = int(data["p"])
   private_key1 = int(data["private_key1"])
   private_key2 = int(data["private_key2"])

   # Check for valid input
   if private_key1 <= 0 or private_key2 <= 0:
      print("Private keys must be greater than 0.")
      sys.exit()

   point_g = (point_x, point_y)
   curve = ECC(a, b, p, point_g)
   dh = DiffieHellman(curve, point_g)

   print("\nprivate key 1: {}".format(private_key1))
   print("private key 2: {}".format(private_key2))

   public_key1 = dh.generate_public_key(private_key1)
   print("\nPublic key associated with private key 1: \n{}\n".format(public_key1))

   public_key2 = dh.generate_public_key(private_key2)
   print("Public key associated with private key 2: \n{}\n".format(public_key2))

   secret_pr1_pub2 = dh.secret_key(private_key1, public_key2)
   print("Secret key for private key 1 and public key 2: \n{}\n".format(secret_pr1_pub2))
   
   secret_pr2_pub1 = dh.secret_key(private_key2, public_key1)
   print("Secret key for private key 2 and public key 1: \n{}\n".format(secret_pr1_pub2))

   print("Secret keys are the same: {}\n".format(secret_pr1_pub2 == secret_pr2_pub1))

if __name__ == "__main__":
   main(sys.argv[1:])