# CS6001-ECC
Diffie Hellman Elliptic Curve Key Exchange

Authors:  Quincy Conduff, Scott Payne, Colin Conduff

# Usage:

`python3 ecc_cli.py --input example1.json`

The example1.json file includes input for x, y, a, b, p, private key 1, and private key 2.

# Unit tests:
`python3 ecc_test.py`
`python3 diffie_hellman_test.py`

# Software Requirements:
python version ~3.5

# Files included in project:  

## ecc_cli.py
	
	Command line interface for ECC and Diffie Hellman Key Exchange

	Given a json file containing input, generates public keys and a shared secret using Diffie Hellman Key Exchange.

## ecc_impl.py

	Elliptic Curve Cryptography implementation

## ecc_test.py
	
	Unit tests for elliptic curve implementation

## diffie_hellman.py
	
	Implementation of Elliptic Curve Diffie-Hellman Key Agreement Protocol 

## diffie_hellman_test.py

	Unit tests for Elliptic Curve Diffie-Hellman Key Agreement Protocol 