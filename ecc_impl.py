class ECC:

    
    """
    Elliptic Curve for use in cryptographic algorithms

    Parameters:
        E_p(a,b) => y^2 = x^3 + a*x + b % p
        base_point = (x,y)
    """
    

    def __init__(self, a, b, p, base_point):
        self.curve = (a,b,p)
        self.base_point = base_point
        self.double_base_point = self.double_point(base_point)
        # self.set_window_size(4)


    def xgcd(self, b, n):
        x0, x1, y0, y1 = 1, 0, 0, 1
        while n != 0:
            q, b, n = b // n, n, b % n
            x0, x1 = x1, x0 - q * x1
            y0, y1 = y1, y0 - q * y1
        return b, x0, y0


    def inverse(self, b):
        g, x, _ = self.xgcd(b, self.curve[2])
        if g == 1:
            return x % self.curve[2]


    def add_points(self, p, q):
        """
        Add two points on the curve

        Args:
            p: Point (x,y) on the curve
            q: Point (x',y') on the curve

        Return:
            (x,y): p + q
        """
        delta = 0

        if p == None or q == None:
            return p if q == None else q
        elif p[0] == q[0] and p[1] == q[1]:
            delta = (3 * p[0]**2 + self.curve[0]) * self.inverse(2 * p[1]) % self.curve[2]
        else:
            delta = (p[1] - q[1]) * self.inverse((p[0] - q[0])) % self.curve[2]

        x = (delta * delta - p[0] - q[0]) % self.curve[2]
        y = (delta * (p[0] - x) - p[1]) % self.curve[2]

        return (x,y)

    
    def double_point(self, p, k = 1):
        """
        Takes a point on the curve and performs 2^k * p

        Args:
            p: Point (x,y) on the curve
            k: number of times to perform doubling

        Return:
            Q: Point (x',y') = 2^k * p
        """
        Q = p
        for i in range(0,k):
            Q = self.add_points(Q,Q)
        return Q

    """
    def set_window_size(self, r):
        self.r = r
        self.window_table = [None,self.base_point,self.double_base_point]
        for i in range(3, 2**r - 2):
            if i % 2 == 0:
                self.window_table.append(self.add_points(self.window_table[i - 2],
                                                         self.window_table[i - 2]))
            else:
                self.window_table.append(self.add_points(self.window_table[i - 2],
                                                         self.double_base_point))
    """
    
    def base_point_mult(self, k):
        """
        Perform k * base_point

        Args:
            k: integer for number of base_point additions

        Return:
            Q: Point (x,y) = k * base_point
        """
        Q = None
        for i in [1 if digit == '1' else 0 for digit in bin(k)[2:]]:
            Q = self.double_point(Q)
            if i == 1:
                Q = self.add_points(Q, self.base_point)
                
        return Q

    #implement sliding window multiplication?


if __name__ == "__main__":

    
    # Testing curve P-192
    print("Testing curve P-192")
    x = ECC(-3, # a
            0x64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1, # b
            6277101735386680763835789423207666416083908700390324961279, # p
            (0x188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012, # Gx
             0x07192b95ffc8da78631011ed6b24cdd573f977a11e794811)) # Gy

    for i in range(1,6):
        test = x.base_point_mult(i)
        print(i, hex(test[0]), hex(test[1]))

    large_k = 6277101735386680763835789423176059013767194773182842284072
    out = x.base_point_mult(large_k)
    print(large_k, hex(out[0]), hex(out[1]))

    #Testing curve P-224
    print("Testing curve P-224")
    x = ECC(-3, # a
            0xb4050a850c04b3abf54132565044b0b7d7bfd8ba270b39432355ffb4, # b
            26959946667150639794667015087019630673557916260026308143510066298881, # p
            (0xb70e0cbd6bb4bf7f321390b94a03c1d356c21122343280d6115c1d21, # Gx
             0xbd376388b5f723fb4c22dfe6cd4375a05a07476444d5819985007e34)) # Gy

    for i in range(1,6):
        test = x.base_point_mult(i)
        print(i, hex(test[0]), hex(test[1]))
        
    #Testing curve P-256
    print("Testing curve P-256")
    x = ECC(-3, # a
            0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b, # b
            115792089210356248762697446949407573530086143415290314195533631308867097853951, # p
            (0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296, # Gx
             0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5)) # Gy

    for i in range(1,6):
        test = x.base_point_mult(i)
        print(i, hex(test[0]), hex(test[1]))
