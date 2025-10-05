from Crypto.Util.number import getPrime, bytes_to_long, long_to_bytes
import random
import math

def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, x, y = egcd(b % a, a)
        return (g, y - (b // a) * x, x)
 
# x = mulinv(b) mod n, (x * b) % n == 1
def mulinv(b, n):
    g, x, _ = egcd(b, n)
    print(g,x,_)
    if g == 1:
        return x % n
    
class PracticalKaraCrypt:
    def __init__(self, key_size=512):
        self.key_size = key_size
        self.p = getPrime(key_size // 2)
        self.q = getPrime(key_size // 2)
        self.n = self.p * self.q
        print('n: ',self.n)
        self.e = 65537  
        self.d = mulinv(self.e,(self.p-1)*(self.q-1))  
        print('d: ',self.d)
        
    def karatsuba_encrypt(self, message):
        m = bytes_to_long(message)
        n_len = len(str(self.n))
        m_len = len(str(m))
        split_point = min(n_len // 2, m_len // 2)
        
        if split_point == 0:
            return pow(m, self.e, self.n)
        
        power = 10**split_point
        high_m, low_m = divmod(m, power)
        c_high = pow(high_m, self.e, self.n)
        c_low = pow(low_m, self.e, self.n)
        c_sum = pow(high_m + low_m, self.e, self.n)
        
        return {
            'c_high': c_high,
            'c_low': c_low, 
            'c_sum': c_sum,
            'split': split_point
        }
    
kc = PracticalKaraCrypt()
message = b"donguCTF{....}"

ciphertext = kc.karatsuba_encrypt(message)
print(f"Зашифровано: {ciphertext}")


