
import array

class DigitalSignatureParameters:
    """
This class contains all nessecary settings and parameters of digital signature,
according to GOST R 34.10-2012. Also it contains mathematical methods for working
with points of ellipting curve stored in the class instance.
    """
    def __init__(self, p, elliptic_curve, m, q, x_p, y_p, hash_func):
        """
Stores digital signature parameters in created class instance.
Checks if digital signature is valid using constraints from GOST R 24.10-2012.

p : BigInteger
elliptic_curve : integer J or tuple of integers (a, b)
m, q, x_p, y_p : BigIntegers
hash_func : function taking array of bytes and returning array of 64 bytes.
        """
        self.p = p
        if isinstance(elliptic_curve, tuple):
            self.a, self.b = elliptic_curve
            assert(4 * self.a**3 + 27 * self.b**2 % p != 0)
            self.J = 1728 * self.div_mod_p(4 * self.a**3, 4 * self.a**3 + 27 * self.b**2) % p
        else:
            self.J = elliptic_curve
            assert(self.J != 0 and self.J != 1728)
            k = self.div_mod_p(self.J, 1728 - self.J)
            self.a = 3 * k % p
            self.b = 2 * k % p
        self.m = m
        self.q = q
        self.x_p = x_p
        self.y_p = y_p
        self.hash_func = hash_func
        assert(p > 3)
        #assert(isprime(p))  we have no simple methods for checking this
        assert(m % q == 0 and m // q >= 1)
        assert(self.mult((x_p, y_p), q) == None)
        assert(2**254 < q < 2**256 or 2**508 < q < 2**512)
        if 2**254 < q < 2**256:
            B = 31
        else:
            B = 131
        for t in range(1, B + 1):
            assert(self.pow_mod_p(p, t, q) != 1)
        assert(m != p)
        assert(self.J != 0 and self.J != 1728)

    def pow_mod_p(self, base, power, mod):
        """
Modular exponentiation by squaring (quick modular exponentiation).

All arguments and result are BigIntegers.
        """
        if power == 0:
            assert(base == 0)
            return 1
        res = 1
        base = base % mod
        while power != 0:
            if power % 2 == 1:
                res = res * base % mod
            base = (base * base) % mod
            power //= 2
        return res

    def div_mod_p(self, a, b):
        """
Returns a / b in the prime field with cardinality self.p.
That means returning a * (b^(-1)) % self.p.
According to Fermat's little theorem, b^(self.p - 1) = 1 (mod self.p).
That means b^(-1) = b^(self.p - 2) (mod self.p).
We compute b^(self.p - 2) using quick modular exponentiation.

All arguments and result are BigIntegers.
        """
        a = a % self.p
        b = b % self.p
        return a * self.pow_mod_p(b, self.p - 2, self.p) % self.p

    def add(self, p1, p2):
        """
Adds two points on the elliptic curve.

Point is None for zero point.
Point is a tuple of two BigIntegers otherwise.
Returns point, sum of two input points.
        """
        if p1 is None:
            return p2
        if p2 is None:
            return p1
        x1, y1 = p1
        x2, y2 = p2
        if x1 != x2:
            l = self.div_mod_p(y2 - y1, x2 - x1)
            x3 = (l * l - x1 - x2) % self.p
            y3 = (l * (x1 - x3) - y1) % self.p
            return (x3, y3)
        elif y1 == y2 and y1 != 0:
            l = self.div_mod_p(3 * x1**2 + self.a, 2 * y1)
            x3 = (l**2 - 2 * x1) % self.p
            y3 = (l * (x1 - x3) - y1) % self.p
            return (x3, y3)
        else:
            return None

    def mult(self, p, k):
        """
Multiplies point of the elliptic curve p by BigInteger k.
The algorithm is similar to the quick exponential by squaring,
it may be called "quick multiplication by doubling".

p : point (i. e., None or tuple(BigInteger, BigInteger))
k : BigInteger
Returns point (i. e. None or tuple(BigInteger, BigInteger))
        """
        res = None
        while k != 0:
            if k % 2 == 1:
                res = self.add(res, p)
            p = self.add(p, p)
            k //= 2
        return res


def generate_public_key(secret_key, parameters):
    """
Given a secret key and parameters, generates public key
according to GOST R 34.10-2012. It means just multiplication of fixed
elliptic curve point by secret key.
Validates secret_key according to GOST R 34.10-2012 constraints.

secret_key : BigInteger
parameters : DigitalSignatureParameters
Returns point, i. e. tuple(BigInteger, BigInteger),
None cannot be obtained because of mathematical guarantees.
    """
    assert(0 < secret_key < parameters.q)
    public_key = parameters.mult((parameters.x_p, parameters.y_p), secret_key)
    assert(public_key != (parameters.x_p, parameters.y_p))
    return public_key


def generate_common_KEK(secret_key, foreign_public_key, parameters, UKM = 1):
    """
Generates Key Encryption Key using ours secret_key, foreign_public_key, parameters and UKM.
UKM makes it more difficult to crack KEK with usage of precomputed tables.
Algorithm is defined in GOST R 34.10-2012 or in GOST R 34.10-2001 (depends on hashing function).

secret_key : BigInteger
foreign_public_key : tuple(BigInteger, BigInteger), not None
parameters : DigitalSignatureParameters
UKM : BigInteger, optional
Returns KEK : array of 64 bytes.
    """
    assert(1 <= UKM <= 2**128 - 1)
    assert(foreign_public_key != (parameters.x_p, parameters.y_p))
    K = parameters.mult(foreign_public_key, (parameters.m / parameters.q * UKM * secret_key % parameters.q))
    assert(K is not None)
    KEK = parameters.hash_func((K[0] * (2**256) + K[1]).to_bytes(512, 'big'))
    return KEK


def GOST34112012H256(msg):
    """
Hashing algorithm defined in GOST R 34.11-2012.

msg : array of bytes
Returns array of 64 bytes.
    """
    pi_sharp = [
        252, 238, 221, 17, 207, 110, 49, 22, 251, 196, 250, 218, 35, 197, 4, 77, 233, 119, 240,
        219, 147, 46, 153, 186, 23, 54, 241, 187, 20, 205, 95, 193, 249, 24, 101, 90, 226, 92, 239,
        33, 129, 28, 60, 66, 139, 1, 142, 79, 5, 132, 2, 174, 227, 106, 143, 160, 6, 11, 237, 152, 127,
        212, 211, 31, 235, 52, 44, 81, 234, 200, 72, 171, 242, 42, 104, 162, 253, 58, 206, 204, 181,
        112, 14, 86, 8, 12, 118, 18, 191, 114, 19, 71, 156, 183, 93, 135, 21, 161, 150, 41, 16, 123,
        154, 199, 243, 145, 120, 111, 157, 158, 178, 177, 50, 117, 25, 61, 255, 53, 138, 126, 109,
        84, 198, 128, 195, 189, 13, 87, 223, 245, 36, 169, 62, 168, 67, 201, 215, 121, 214, 246, 124,
        34, 185, 3, 224, 15, 236, 222, 122, 148, 176, 188, 220, 232, 40, 80, 78, 51, 10, 74, 167, 151,
        96, 115, 30, 0, 98, 68, 26, 184, 56, 130, 100, 159, 38, 65, 173, 69, 70, 146, 39, 94, 85, 47,
        140, 163, 165, 125, 105, 213, 149, 59, 7, 88, 179, 64, 134, 172, 29, 247, 48, 55, 107, 228,
        136, 217, 231, 137, 225, 27, 131, 73, 76, 63, 248, 254, 141, 83, 170, 144, 202, 216, 133, 97,
        32, 113, 103, 164, 45, 43, 9, 91, 203, 155, 37, 208, 190, 229, 108, 82, 89, 166, 116, 210,
        230, 244, 180, 192, 209, 102, 175, 194, 57, 75, 99, 182
    ]

    C = [
        0xb1085bda1ecadae9ebcb2f81c0657c1f2f6a76432e45d016714eb88d7585c4fc4b7ce09192676901a2422a08a460d31505767436cc744d23dd806559f2a64507,
        0x6fa3b58aa99d2f1a4fe39d460f70b5d7f3feea720a232b9861d55e0f16b501319ab5176b12d699585cb561c2db0aa7ca55dda21bd7cbcd56e679047021b19bb7,
        0xf574dcac2bce2fc70a39fc286a3d843506f15e5f529c1f8bf2ea7514b1297b7bd3e20fe490359eb1c1c93a376062db09c2b6f443867adb31991e96f50aba0ab2,
        0xef1fdfb3e81566d2f948e1a05d71e4dd488e857e335c3c7d9d721cad685e353fa9d72c82ed03d675d8b71333935203be3453eaa193e837f1220cbebc84e3d12e,
        0x4bea6bacad4747999a3f410c6ca923637f151c1f1686104a359e35d7800fffbdbfcd1747253af5a3dfff00b723271a167a56a27ea9ea63f5601758fd7c6cfe57,
        0xae4faeae1d3ad3d96fa4c33b7a3039c02d66c4f95142a46c187f9ab49af08ec6cffaa6b71c9ab7b40af21f66c2bec6b6bf71c57236904f35fa68407a46647d6e,
        0xf4c70e16eeaac5ec51ac86febf240954399ec6c7e6bf87c9d3473e33197a93c90992abc52d822c3706476983284a05043517454ca23c4af38886564d3a14d493,
        0x9b1f5b424d93c9a703e7aa020c6e41414eb7f8719c36de1e89b4443b4ddbc49af4892bcb929b069069d18d2bd1a5c42f36acc2355951a8d9a47f0dd4bf02e71e,
        0x378f5a541631229b944c9ad8ec165fde3a7d3a1b258942243cd955b7e00d0984800a440bdbb2ceb17b2b8a9aa6079c540e38dc92cb1f2a607261445183235adb,
        0xabbedea680056f52382ae548b2e4f3f38941e71cff8a78db1fffe18a1b3361039fe76702af69334b7a1e6c303b7652f43698fad1153bb6c374b4c7fb98459ced,
        0x7bcd9ed0efc889fb3002c6cd635afe94d8fa6bbbebab076120018021148466798a1d71efea48b9caefbacd1d7d476e98dea2594ac06fd85d6bcaa4cd81f32d1b,
        0x378ee767f11631bad21380b00449b17acda43c32bcdf1d77f82012d430219f9b5d80ef9d1891cc86e71da4aa88e12852faf417d5d9b21b9948bc924af11bd720,
    ]

    tau = [
        0, 8, 16, 24, 32, 40, 48, 56, 1, 9, 17, 25, 33, 41, 49, 57, 2, 10, 18, 26, 34, 42, 50, 58,
        3, 11, 19, 27, 35, 43, 51, 59, 4, 12, 20, 28, 36, 44, 52, 60, 5, 13, 21, 29, 37, 45, 53, 61, 6, 14,
        22, 30, 38, 46, 54, 62, 7, 15, 23, 31, 39, 47, 55, 63
    ]

    A = [
        0x8e20faa72ba0b470, 0x47107ddd9b505a38, 0xad08b0e0c3282d1c, 0xd8045870ef14980e,
        0x6c022c38f90a4c07, 0x3601161cf205268d, 0x1b8e0b0e798c13c8, 0x83478b07b2468764,
        0xa011d380818e8f40, 0x5086e740ce47c920, 0x2843fd2067adea10, 0x14aff010bdd87508,
        0x0ad97808d06cb404, 0x05e23c0468365a02, 0x8c711e02341b2d01, 0x46b60f011a83988e,
        0x90dab52a387ae76f, 0x486dd4151c3dfdb9, 0x24b86a840e90f0d2, 0x125c354207487869,
        0x092e94218d243cba, 0x8a174a9ec8121e5d, 0x4585254f64090fa0, 0xaccc9ca9328a8950,
        0x9d4df05d5f661451, 0xc0a878a0a1330aa6, 0x60543c50de970553, 0x302a1e286fc58ca7,
        0x18150f14b9ec46dd, 0x0c84890ad27623e0, 0x0642ca05693b9f70, 0x0321658cba93c138,
        0x86275df09ce8aaa8, 0x439da0784e745554, 0xafc0503c273aa42a, 0xd960281e9d1d5215,
        0xe230140fc0802984, 0x71180a8960409a42, 0xb60c05ca30204d21, 0x5b068c651810a89e,
        0x456c34887a3805b9, 0xac361a443d1c8cd2, 0x561b0d22900e4669, 0x2b838811480723ba,
        0x9bcf4486248d9f5d, 0xc3e9224312c8c1a0, 0xeffa11af0964ee50, 0xf97d86d98a327728,
        0xe4fa2054a80b329c, 0x727d102a548b194e, 0x39b008152acb8227, 0x9258048415eb419d,
        0x492c024284fbaec0, 0xaa16012142f35760, 0x550b8e9e21f7a530, 0xa48b474f9ef5dc18,
        0x70a6a56e2440598e, 0x3853dc371220a247, 0x1ca76e95091051ad, 0x0edd37c48a08a6d8,
        0x07e095624504536c, 0x8d70c431ac02a736, 0xc83862965601dd1b, 0x641c314b2b8ee083,
    ]

    def mult_b_A(b):
        c = 0
        for i in range(64):
            if b % 2 == 1:
                c = c ^ A[63-i]
            b = b // 2
        return c

    def MSB256(val):
        return val // (2**256)

    def int512(msg):
        res = 0
        for i in range(len(msg)):
            res += (2**(8 * i)) * msg[-i-1]
        return res

    def S(m):
        res = 0
        for i in range(64):
            byte = m // (2 ** (8 * i)) % 256
            res += pi_sharp[byte] * (2 ** (8 * i))
        return res

    def P(m):
        res = 0
        for i in range(64):
            byte = m // (2 ** (8 * tau[i])) % 256
            res += byte * (2 ** (8 * i))
        return res

    def L(m):
        res = 0
        for i in range(8):
            block = m // (2 ** (64 * i)) % (2**64)
            res += mult_b_A(block) * (2 ** (64 * i))
        return res

    def X(K, m):
        return K ^ m

    def E(K, m):
        res = X(K, m)
        for i in range(2, 14):
            res = L(P(S(res)))
            K = L(P(S(K ^ C[i - 2])))
            res = X(K, res)
        return res

    def g(h, m, N):
        return E(L(P(S(h ^ N))), m) ^ h ^ m

    IV = 0
    for i in range(64):
        IV += 2 ** (i * 8)
    h = IV
    N = 0
    Sigma = 0

    while len(msg) * 8 >= 512:
        m = int512(msg[-512 // 8:])
        h = g(h, m, N)
        N = (N + 512) % (2**512)
        Sigma = (Sigma + m) % (2**512)
        msg = msg[:-512 // 8]

    m = 2**(len(msg)*8) + int512(msg)
    h = g(h, m, N)
    N = (N + len(msg) * 8) % (2**512)
    Sigma = (Sigma + m) % (2**512)
    h = g(h, N, 0)
    h = MSB256(g(h, Sigma, 0))

    return h.to_bytes(64, 'big')


def cipher_feedback_mode_encode(msg, CEK, IV = int(0).to_bytes(8, 'big')):
    """
Encodes message using CEK and IV according to GOST 28147-89.

msg : array of bytes
CEK : array of 32 bytes
IV : array of 8 bytes
    """
    assert(len(CEK) == 32)
    assert(len(IV) == 8)
    last_block = IV
    res = b''
    for i in range(0, len(msg), 8):
        gamma = GOST2814789ECB_encode(last_block, CEK)
        block = msg[i: min(i + 8, len(msg))]
        encrypted_block = b''
        for j in range(len(block)):
            encrypted_block += int(block[j] ^ gamma[j]).to_bytes(1, 'big')
        res += encrypted_block
        last_block = encrypted_block
    return res


def cipher_feedback_mode_decode(msg, CEK, IV = int(0).to_bytes(8, 'big')):
    """
Decodes message using CEK and IV according to GOST 28147-89.

msg : array of bytes
CEK : array of 32 bytes
IV : array of 8 bytes
    """
    assert(len(CEK) == 32)
    assert(len(IV) == 8)
    last_block = IV
    res = b''
    for i in range(0, len(msg), 8):
        gamma = GOST2814789ECB_encode(last_block, CEK)
        block = msg[i: min(i + 8, len(msg))]
        decrypted_block = b''
        for j in range(len(block)):
            decrypted_block += int(block[j] ^ gamma[j]).to_bytes(1, 'big')
        res += decrypted_block
        last_block = block
    return res


class ECB_helper:
  def __init__(self):
    self.sboxes = [[4,10,9,2,13,8,0,14,6,11,1,12,7,15,5,3],[2,14,11,4,12,6,13,15,10,2,3,8,1,0,7,5,9],[3,5,8,1,13,10,3,4,2,14,15,12,7,6,0,9,11],[4,7,13,10,1,0,8,9,15,14,4,6,12,11,2,5,3],[5,6,12,7,1,5,15,13,8,4,10,9,14,0,3,11,2],[6,4,11,10,0,7,2,1,13,3,6,8,5,9,12,15,14],[7,13,11,4,1,3,15,5,9,0,10,14,7,6,8,2,12],[8,1,15,13,0,5,7,10,4,9,2,3,14,6,11,8,12]]
  
  # circular left shift : shift block to the left by a bits, if block is number of max bits
  # block, a, max : int
  # return value : int
  def cycle_left(self, block, a, max):
    return ((block << a) % (2**max)) | (block >> (max - a))
  
  
  # circular right shift : shift block to the right by a bits, if block is number of max bits
  # block, a, max : int
  # return value : int
  def cycle_right(self, block, a, max):
    return ((block << a) % (2**max)) | (block >> (max - a))
  
  # block : int
  # return value : int
  def apply_sbox(self, block):
    res = 0;
    for i in range(8):
      index = block % 16
      block = block // 16
      res = res * 16 + self.sboxes[i][index]
    return res
  
  # same as int512
  def int32(self, msg):
    res = 0
    for i in range(len(msg)):
        res += (2**(8 * i)) * msg[-i-1]
    return res
  
  # main function f of the round in ECB
  # b : 32 bit int
  # k : 32 bit subkey
  # return value : int
  def f(self, b, k):
    return self.cycle_left(self.apply_sbox((b + k) % (2**32)), 11, 32)
  
  
#GOST 28147-89 ECB
# plain : array of bytes (length must be 8*n)
# key : array of bytes (length must be 32)
# return value : array of bytes
def GOST2814789ECB_encode(plain, key):
  res = list()
  keys = list()
  helper = ECB_helper()
  if len(plain) % 8 != 0:
    return False
  for i in range(32):
    if i < 24:
      j = i % 8
    else:
      j = 7 - i % 8
    keys.append(helper.int32(key[j * 4 : (j + 1) * 4]))
    
  for i in range(len(plain) // 8):
    a = helper.int32(plain[i * 8 : i * 8 + 4])
    b = helper.int32(plain[i * 8 + 4 : i * 8 + 8])
    for j in range(32):
      tmp = b
      b = helper.f(b, keys[j]) ^ a
      a = tmp
    res.extend(a.to_bytes(4, 'big'))
    res.extend(b.to_bytes(4, 'big'))
  return res
  
# cipher : array of bytes (length must be 8*n)
# key : array of bytes (length must be 32)
# return value : array of bytes
def GOST2814789ECB_decode(cipher, key):
  res = list()
  keys = list()
  helper = ECB_helper()
  for i in range(32):
    if i < 24:
      j = i % 8
    else:
      j = 7 - i % 8
    keys.append(helper.int32(key[j * 4 : (j + 1) * 4]))
    
  for i in range(len(cipher) // 8):
    a = helper.int32(cipher[i * 8 : i * 8 + 4])
    b = helper.int32(cipher[i * 8 + 4 : i * 8 + 8])
    for j in range(32):
      tmp = a
      a = helper.f(a, keys[31 - j]) ^ b
      b = tmp
    res.extend(a.to_bytes(4, 'big'))
    res.extend(b.to_bytes(4, 'big'))
  bytes = len(res)
  return helper.int32(res).to_bytes(bytes, 'big')

# plain : array of bytes (length must be 8*n)
# key : arrays of bytes (length must be 32)
# IV : int (must be < 2^64)
# return value : array of 4 bytes
def GOST2814789IMIT(plain, key, IV = 0):
  res = list()
  keys = list()
  if len(plain) % 8 != 0:
    return False
  helper = ECB_helper()
  for i in range(16):  
    keys.append(helper.int32(key[(i % 16) * 4 : ((i % 16) + 1) * 4]))
  last_a = IV // (2**32)
  last_b = IV % (2**32)
  for i in range(len(plain) // 8):
    a = last_a ^ helper.int32(plain[i * 8 : i * 8 + 4])
    b = last_b ^ helper.int32(plain[i * 8 + 4 : i * 8 + 8]) 
    for j in range(16):
      tmp = b
      b = helper.f(b, keys[j]) ^ a
      a = tmp
    last_a = a
    last_b = b
  res.extend(b.to_bytes(4, 'big'))
  return res

# CEK and KEK : arrays of bytes
# return value: list of bytes, (UKM | CEK_ENC | CEK_MAC)
def GOST2814789KeyWrap(CEK, KEK):
  import random
  helper = ECB_helper()
  UKM = list()
  for i in range(8):
    UKM.append(random.randint(0,256))
  CEK_MAC = GOST2814789IMIT(CEK, KEK, helper.int32(UKM))
  CEK_ENC = GOST2814789ECB_encode(CEK, KEK)
  res = UKM
  res.extend(CEK_ENC)
  res.extend(CEK_MAC)
  return res
 
# keyWrap : array of bytes, length must be 44
# KEK : array of bytes
# return value : CEK - array of bytes, or false in case of error
def GOST2814789KeyUnWrap(keyWrap, KEK):
  if len(keyWrap) != 44:
    return False
  helper = ECB_helper()
  UKM = keyWrap[0 : 8]
  CEK_ENC = keyWrap[8 : 40]
  CEK_MAC = keyWrap[40 : 44]
  CEK = GOST2814789ECB_decode(CEK_ENC, KEK)
  if helper.int32(CEK_MAC) == helper.int32(GOST2814789IMIT(CEK, KEK, helper.int32(UKM))):
    return CEK
  else:
    return False

    
base_parameters_1 = DigitalSignatureParameters(
0x8000000000000000000000000000000000000000000000000000000000000431,
(0x7, 0x5FBFF498AA938CE739B8E022FBAFEF40563F6E6A3472FC2A514C0CE9DAE23B7E),
0x8000000000000000000000000000000150FE8A1892976154C59CFC193ACCF5B3,
0x8000000000000000000000000000000150FE8A1892976154C59CFC193ACCF5B3,
2, 0x8E2A8A0E65147D4BD6316030E16D19C85C97F0A9CA267122B96ABBCEA7E8FC8,
GOST34112012H256)

base_parameters_2 = DigitalSignatureParameters(
0x4531ACD1FE0023C7550D267B6B2FEE80922B14B2FFB90F04D4EB7C09B5D2D15DF1D852741AF4704A0458047E80E4546D35B8336FAC224DD81664BBF528BE6373,
(0x7, 0x1CFF0806A31116DA29D8CFA54E57EB748BC5F377E49400FDD788B649ECA1AC4361834013B2AD7322480A89CA58E0CF74BC9E540C2ADD6897FAD0A3084F302ADC),
0x4531ACD1FE0023C7550D267B6B2FEE80922B14B2FFB90F04D4EB7C09B5D2D15DA82F2D7ECB1DBAC719905C5EECC423F1D86E25EDBE23C595D644AAF187E6E6DF,
0x4531ACD1FE0023C7550D267B6B2FEE80922B14B2FFB90F04D4EB7C09B5D2D15DA82F2D7ECB1DBAC719905C5EECC423F1D86E25EDBE23C595D644AAF187E6E6DF,
0x24D19CC64572EE30F396BF6EBBFD7A6C5213B3B3D7057CC825F91093A68CD762FD60611262CD838DC6B60AA7EEE804E28BC849977FAC33B4B530F1B120248A9A,
0x2BB312A43BD2CE6E0D020613C857ACDDCFBF061E91E5F2C3F32447C259F39B2C83AB156D77F1496BF7EB3351E1EE4E43DC1A18B91B24640B6DBB92CB1ADD371E,
GOST34112012H256)
