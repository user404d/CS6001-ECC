class DiffieHellman(object):
    """ 
    Elliptic Curve Diffie-Hellman Key Agreement Protocol 

    An anonymous key agreement protocol that allows two parties,
    to create a shared secret over an insecure channel using
    elliptic curve public/private key pairs.

    source: (https://en.wikipedia.org/wiki/Elliptic_curve_Diffie%E2%80%93Hellman)
    """

    def __init__(self, elliptic_curve, point_g):
        """ 
        Initialize diffie-hellman key agreement protocol.

        Args:
            elliptic_curve: an ECC object from ecc_impl
            point_g: (x, y) tuple, a pair of ints corresponding to a point
        """
        self.elliptic_curve = elliptic_curve
        self.point_g = point_g

    def generate_public_key(self, private_key):
        """
        Generate a public key using the private key and point g.

        Args:
            private_key: a prime integer

        Return: a pair of integers (tuple) corresponding to a point
        """
        if private_key < 0:
            raise ValueError
        return self.elliptic_curve.double_point(self.point_g, private_key)

    def secret_key(self, private_key, public_key):
        """
        Generate a shared secret key using private and public keys.

        Args:
            private_key: a prime integer
            public_key: a pair of integers (tuple) corresponding to a point on the curve

        Return: a pair of integers (tuple) corresponding to a point on the curve
        """
        return self.elliptic_curve.double_point(public_key, private_key)

if __name__ == "__main__":
    from ecc_impl import ECC

    # using curve P-192
    
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

    print("private_key1: {}, \npublic_key1 {}, \nprivate_key2: {}, \npublic_key2: {}, \nprivate_key3: {}, \npublic_key3: {}"
        .format(private_key1, public_key1, private_key2, public_key2, private_key3, public_key3))
    print("dh.secret_key(private_key1, public_key2) {}".format(dh.secret_key(private_key1, public_key2)))
    print("dh.secret_key(private_key2, public_key1) {}".format(dh.secret_key(private_key2, public_key1)))
