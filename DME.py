from charm.toolbox.pairinggroup import ZR, G1, pair
from charm.toolbox.hash_module import Hash
import pickle
import base64
import random
import string


class DM:

    def __init__(self, groupObj=None):
        if groupObj is None:
            from charm.toolbox.pairinggroup import PairingGroup
            from charm.toolbox.hash_module import Hash
            groupObj = PairingGroup('SS512', secparam=512)
        global group
        group = groupObj
        mask = 'ed27dbfb02752e0e16bc4502d6c732bc5f1cc92ba19b2d93a4e95c597ca42753e93550b52f82b6c13fb8cc0c2fc64487'
        self._mask = bytes.fromhex(mask)

    def setup(self):
        a, b, c = group.random(ZR), group.random(ZR), group.random(ZR)
        g = group.random(G1)
        G = g ** a
        G_ = g ** c

        pk = (g, G, G_)
        sk = (a, b, c)
        if (debug):
            print("Public parameters...")
            group.debug(pk)
            print("Secret parameters...")
            group.debug(sk)
        return (pk, sk)

    def serialize_public_key(self, pk):
        return pickle.dumps(tuple(group.serialize(x) for x in pk))

    def deserialize_public_key(self, bitstring):
        pieces = pickle.loads(bitstring)
        return tuple(group.deserialize(p) for p in pieces)

    def serialize_secret_key(self, sk):
        return pickle.dumps(tuple(group.serialize(x) for x in sk))

    def deserialize_secret_key(self, bitstring):
        pieces = pickle.loads(bitstring)
        return tuple(group.deserialize(p) for p in pieces)

    def Hr(self, X):
        return group.hash(X, G1)

    def Hs(self, X):
        # Both H and H' are computed from the same method group.hash()
        # In order to make them different, we apply a fixed mask to the
        # inputs of H'
        X = bytes([a ^ b for (a, b) in zip(X.encode(), self._mask)])
        return group.hash(X, G1)

    def H1(self, X):
        x = group.serialize(X)[2:-1]
        res = group.hash(x, ZR)
        return res

    def prg(self, X):
        k = str(X)
        r = k[0:24]
        l = k[24:]

        r1 = r[0:12]
        r2 = r[12:]
        l1 = l[0:12]
        l2 = l[12:]

        temp1 = bytes([ord(a) ^ ord(b) for (a, b) in zip(r1, r2)])
        x1 = group.hash(temp1, ZR)

        temp2 = bytes([ord(a) ^ ord(b) for (a, b) in zip(l1, l2)])
        y1 = group.hash(temp2, ZR)

        # x1 = X * 2
        # y1 = X * 3
        # result = (x1, y1)
        return x1, y1

    def skgen(self, sk, S):
        (_, b, _) = sk
        eks = self.Hs(S) ** b
        return eks

    def rkgen(self, sk, R):
        (a, b, _) = sk
        Hr = self.Hr(R)
        dkr1 = Hr ** a
        dkr2 = Hr ** b
        dkr = (dkr1, dkr2)
        return dkr

    def drgen(self, sk, R):
        (a, b, c) = sk
        Hr = self.Hr(R)
        dkr1 = Hr ** a
        dkr2 = Hr ** b
        dkr_ = (dkr1, dkr2)
        tr = group.random(ZR)
        h_idr = group.hash(R, ZR)
        fk1 = c * h_idr + tr
        fk2 = Hr ** tr
        fkr = (fk1, fk2)
        return dkr_, fkr

    def serialize_drgen(self, dkr_: tuple, fkr: tuple):
        return pickle.dumps(tuple(group.serialize(x) for x in dkr_+fkr))

    def deserialize_drgen(self, bitstring):
        pieces = pickle.loads(bitstring)
        dkr1, dkr2, fk1, fk2 = tuple(group.deserialize(p) for p in pieces)
        dkr_ = (dkr1, dkr2)
        fkr = (fk1, fk2)
        return dkr_, fkr

    def bytes_to_int(self, bytes):
        result = 0
        for b in bytes:
            result = result * 256 + int(b)
        return result

    def int_to_bytes_to_str(self, value, length):
        result = []
        for i in range(0, length):
            result.append(value >> (i * 8) & 0xff)
        result.reverse()
        res_str = ''
        for num in result:
            res_str += chr(num)
        return res_str

    def padding_m(self, byte_m: bytes):
        m_length = len(byte_m)
        int_m = self.bytes_to_int(byte_m)
        str_m = str(int_m)
        while len(str_m) < 48:
            str_m += '0'
        res_m = int(str_m)
        return res_m, m_length

    def depadd_m(self, m: int, m_length: int):
        str_m = str(m)
        tag = 0
        for i in range(len(str_m) - 1, -1, -1):
            if str_m[i] == '0':
                tag += 1
            else:
                break
        res_str_m = str_m[0:len(str_m) - tag]
        return self.int_to_bytes_to_str(int(res_str_m), m_length)

    def gen_random_enc(self):
        U = group.random(G1)
        v = group.random(ZR)
        return U, v

    def pad_int(self, m: int):
        str_m = str(m)
        while len(str_m) < 48:
            str_m += '0'
        res_m = int(str_m)
        return res_m

    def depad_int(self, padded_m: int):
        str_m = str(padded_m)
        tag = 0
        for i in range(len(str_m) - 1, -1, -1):
            if str_m[i] == '0':
                tag += 1
            else:
                break
        res_str_m = str_m[0:len(str_m) - tag]
        return int(res_str_m)

    # Enc
    def encrypt_int_msg(self, pk, eks, idr, m: int):
        res_m = self.pad_int(m)
        # (U, v) = r
        U = group.random(G1)
        v = group.random(ZR)

        print("sender's random is:", base64.urlsafe_b64encode(group.serialize(U)[2:]), int(str(v)))

        (g, G, G_) = pk
        V = g ** v
        k11 = pair(self.Hr(idr), G ** v)
        k12 = pair(self.Hr(idr), U * eks)
        en_k11 = group.serialize(k11)[2:-1]
        en_k12 = group.serialize(k12)[2:-1]
        temp = bytes([a ^ b for (a, b) in zip(en_k11, en_k12)])
        k1 = group.hash(temp, ZR)
        # PRG
        (x1, y1) = self.prg(k1)
        a = group.random(ZR)
        e = res_m + y1 - a * x1
        c = (U, V, a, e)
        return c

    def encrypt_str_msg(self, pk, eks, idr, m: bytes, r):
        res_m, m_length = self.padding_m(m)
        # print("The length of encrypted message is:", m_length)
        print("The length of encrypted message is:", m_length - 2)

        (g, G, G_) = pk
        (U, v) = r
        V = g ** v
        k11 = pair(self.Hr(idr), G ** v)
        k12 = pair(self.Hr(idr), U * eks)
        en_k11 = group.serialize(k11)[2:-1]
        en_k12 = group.serialize(k12)[2:-1]
        temp = bytes([a ^ b for (a, b) in zip(en_k11, en_k12)])
        k1 = group.hash(temp, ZR)
        # PRG
        (x1, y1) = self.prg(k1)
        a = group.random(ZR)
        e = res_m + y1 - a * x1
        c = (U, V, a, e)
        return c

    # DEnc
    def denc(self, pk, eks, idr, idr_, input_m, input_m_):
        m = self.pad_int(input_m)
        m_ = self.pad_int(input_m_)

        (g, G, G_) = pk
        u = group.random(ZR)
        # u = r
        U = g ** u
        k = pair(self.Hr(idr_), G_ ** (group.hash(idr_, ZR) * u))
        v = self.H1(k)
        V = g ** v
        k11 = pair(self.Hr(idr), G ** v)
        k12 = pair(self.Hr(idr), U * eks)
        k21 = pair(self.Hr(idr_), G ** v)
        k22 = pair(self.Hr(idr_), U * (eks ** self.H1(k ** v)))

        en_k11 = group.serialize(k11)[2:-1]
        en_k12 = group.serialize(k12)[2:-1]
        temp = bytes([a ^ b for (a, b) in zip(en_k11, en_k12)])
        k1 = group.hash(temp, ZR)

        en_k21 = group.serialize(k21)[2:-1]
        en_k22 = group.serialize(k22)[2:-1]
        temp1 = bytes([a ^ b for (a, b) in zip(en_k21, en_k22)])
        k2 = group.hash(temp1, ZR)

        r = u
        (x1, y1) = self.prg(k1)
        (x2, y2) = self.prg(k2)
        a = (m - m_ + y1 - y2) / (x1 - x2)
        e = m + y1 - a * x1
        # print("e", e)
        e1 = m_ + y2 - a * x2
        # print("e1", e)

        C = (U, V, a, e)
        return C

    def decrypt(self, dkr, R, idS, C):
        (dkr1, dkr2) = dkr
        (U, V, a, e) = C
        k11 = pair(dkr1, V)
        k12 = pair(self.Hr(R), U) * pair(dkr2, self.Hs(idS))

        en_k11 = group.serialize(k11)[2:-1]
        en_k12 = group.serialize(k12)[2:-1]
        temp = bytes([a ^ b for (a, b) in zip(en_k11, en_k12)])
        k1 = group.hash(temp, ZR)

        # PRG
        (x1, y1) = self.prg(k1)
        m = int(a) * int(x1) + e - y1
        return self.depad_int(m)

    # Dec
    def decrypt_str_message(self, dkr, R, idS, C, msg_length):
        (dkr1, dkr2) = dkr
        (U, V, a, e) = C
        k11 = pair(dkr1, V)
        k12 = pair(self.Hr(R), U) * pair(dkr2, self.Hs(idS))
        en_k11 = group.serialize(k11)[2:-1]
        en_k12 = group.serialize(k12)[2:-1]
        temp = bytes([a ^ b for (a, b) in zip(en_k11, en_k12)])
        k1 = group.hash(temp, ZR)
        # PRG
        (x1, y1) = self.prg(k1)
        m = int(a) * int(x1) + e - y1
        return self.depadd_m(int(str(m)), msg_length)
        # return m

    def test_decrypt(self, dkr, R, idS, C):
        for i in range(len(C)):
            self.decrypt(dkr, R, idS, C[i])

    def sfake(self, pk, eks, idr_, r):
        (g, G, G_) = pk
        u = r
        k = pair(self.Hr(idr_), G_ ** (group.hash(idr_, ZR) * u))
        U = g ** u
        v = self.H1(k)
        eks_ = eks ** self.H1(k ** v)
        r_ = (U, v)
        return eks_, r_

    def test_sfake(self, pk, eks, idr, idr_, m, m_, r):
        for i in range(len(r)):
            self.sfake(pk, eks, idr, idr_, m[i], m[i], r[i])

    def test_rfake(self, idr_, dkr_, fk, C):
        for i in range(len(C)):
            self.rfake(idr_, dkr_, fk, C[i])

    def rfake(self, idr_, dkr_, fkr, C):
        (U, V, a, e) = C
        (fk1, fk2) = fkr
        (dkr_1, dkr_2) = dkr_
        k = pair((self.Hr(idr_) ** fk1) / fk2, U)
        v = self.H1(k)
        dk_r_ = (dkr_1, dkr_2 ** self.H1(k ** v))
        return dk_r_

    def serialize(self, input):
        return base64.urlsafe_b64encode(group.serialize(input)[2:])

    def deserialize(self, bitstring):
        return group.deserialize(b'1:' + base64.urlsafe_b64decode(bitstring))

    def deserialize_eks(self, bitstring):
        return group.deserialize(b'1:' + base64.urlsafe_b64decode(bitstring))

    def serialize_tuple(self, input):
        return pickle.dumps(tuple(group.serialize(x) for x in input))

    def deserialize_tuple(self, bitstring):
        pieces = pickle.loads(bitstring)
        return tuple(group.deserialize(p) for p in pieces)

    def serialize_ciphertext(self, C):
        U, V, a, e = C
        U = base64.b64decode(group.serialize(U)[2:])
        V = base64.b64decode(group.serialize(V)[2:])
        # a = base64.b64decode(group.serialize(a)[2:])
        a = str(a)
        # e = base64.b64decode(group.serialize(e)[2:])
        e = str(e)
        return pickle.dumps((U, V, a, e))

    def deserialize_ciphertext(self, bitstring):
        U, V, a, e = pickle.loads(bitstring)
        U = group.deserialize(b'1:' + base64.b64encode(U))
        V = group.deserialize(b'1:' + base64.b64encode(V))
        # a = group.deserialize(b'1:'+base64.b64encode(a))
        a = int(a)
        # e = group.deserialize(b'1:'+base64.b64encode(e))
        e = int(e)
        return U, V, a, e


def generate_random_str(length):
    """
  string.digits=0123456789
  string.ascii_letters=abcdefghigklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ
  """
    str_list = [random.choice(string.digits + string.ascii_letters) for i in range(length)]
    random_str = ''.join(str_list)
    return random_str


if __name__ == "__main__":
    debug = True
    from charm.toolbox.pairinggroup import PairingGroup

    group = PairingGroup('SS512', secparam=512)
    ME = DM(group)

    (pk, sk) = ME.setup()

    # R = 'alice'
    # S = 'bob'
    # R_ = 'dave'
    # dkr = ME.rkgen(sk, R)
    # eks = ME.skgen(sk, S)

    # (dkr_, fk) = ME.drgen(sk, R)

    eks_bob = ME.skgen(sk, 'bob')
    dkr_bob = ME.rkgen(sk, 'bob')
    eks_alice = ME.skgen(sk, 'alice')
    dkr_alice = ME.rkgen(sk, 'alice')

    (dkr_, fkr) = ME.drgen(sk, 'dave')
    print("dave drgen", base64.urlsafe_b64encode(ME.serialize_drgen(dkr_, fkr)))

    print(base64.urlsafe_b64encode(ME.serialize_public_key(pk)))
    print(base64.urlsafe_b64encode(ME.serialize_secret_key(sk)))

    alice_ek = base64.urlsafe_b64encode(group.serialize(eks_alice)[2:])
    print("alice ek", alice_ek)

    alice_dk = base64.urlsafe_b64encode(ME.serialize_tuple(dkr_alice))
    print("alice dk", alice_dk)

    bob_ek = base64.urlsafe_b64encode(group.serialize(eks_bob)[2:])
    print("bob ek", bob_ek)

    bob_dk = base64.urlsafe_b64encode(ME.serialize_tuple(dkr_bob))
    print("bob dk", bob_dk)

    # M = b'hello'
    # lenth = 2048
    # M = generate_random_str(lenth).encode()
    # m = group.hash(M, ZR)
    #
    # M = b'hello world!'
    #
    # # test Enc
    print("________________test Enc______________")
    # M = 123456
    # r = ME.gen_random_enc()
    # C = ME.encrypt_int_msg(pk, eks, R, M, r)
    # d_m = ME.decrypt(dkr, R, S, C)
    # print("d_m", d_m)

    # test Denc
    print("________________test DEnc______________")
    m = 1234
    m_ = 5678
    C = ME.denc(pk, eks_bob, 'alice', 'dave', m, m_)
    d_m = ME.decrypt(dkr_alice, 'alice', 'bob', C)
    print("d_m", d_m)

    dk_r_ = ME.rfake('dave', dkr_, fkr, C)
    dave_fake_dk = base64.urlsafe_b64encode(ME.serialize_tuple(dk_r_))
    print("dave fake dk", dave_fake_dk)

    d_m_ = ME.decrypt(dk_r_, 'dave', 'bob', C)
    print("d_m'", d_m_)

    # print("_______________test fake________________")
    # (eks_, r_) = ME.sfake(pk, eks, R, R_, m, m_, rr)
    # print("eks'", eks_)
    # print("r'", r_)
    # (dk_r_) = ME.rfake(R_, dkr_, fk, C)
    # print("dk'r'", dk_r_)

    # benchmark
#     import timeit
#     print("______________benchmark______________")
#     setup = '''
# from __main__ import DM
# from DM import generate_random_str
# from charm.toolbox.pairinggroup import ZR,G1,pair
# from charm.toolbox.hash_module import Hash
# import pickle
# import base64
# import random
# import string
# from charm.toolbox.pairinggroup import PairingGroup,pair
# from charm.toolbox.pairinggroup import ZR,G1,pair
# group = PairingGroup('SS512', secparam=512)
# ME = DM(group)
# (pk, sk) = ME.setup()
# R = 'attribute 1'
# S = 'attribute 2'
# R_ = 'attribute 3'
# dkr = ME.rkgen(sk, R)
# eks = ME.skgen(sk, S)
# (dkr_, fk) = ME.drgen(sk, R)
# lenth = 1280
# n = int(lenth / 128)
# l_m = []
# l_m_ = []
# for i in range(n):
#     M = generate_random_str(128).encode()
#     l_m.append(group.hash(M, ZR))
#     M_ = generate_random_str(128).encode()
#     l_m_.append(group.hash(M_, ZR))
# r = 0
#     '''
#     debug = False
#     iters = 5
#     repetitions = 5
#     print("\n=====")
#     print("Benchmarking DM...{} iters, {} repetitions".format(iters, repetitions))
#
#     setupp = '(pk, sk) = ME.setup()'
#     timer = timeit.Timer(setupp, setup=setup)
#     print("setup time (ms):")
#     timings = [time/iters for time in timer.repeat(repetitions, iters)]
#     print('\tmin', 1000*min(timings), '\tavg', 1000*(1.0/repetitions)*sum(timings))
#
#     encryption = 'C = ME.test_enc(pk, eks, R, l_m)'
#     timer = timeit.Timer(encryption, setup=setup)
#     print('Encryption time (ms):')
#     timings = [time/iters for time in timer.repeat(repetitions, iters)]
#     print('\tmin', 1000*min(timings), '\tavg', 1000*(1.0/repetitions)*sum(timings))
#
#     Dencryption = '(C1, rr) = ME.test_denc(pk, eks, R, R_, l_m, l_m_)'
#     timer = timeit.Timer(Dencryption, setup=setup)
#     print('Dencryption time (ms):')
#     timings = [time/iters for time in timer.repeat(repetitions, iters)]
#     print('\tmin', 1000*min(timings), '\tavg', 1000*(1.0/repetitions)*sum(timings))
#
#     sgen = 'ME.skgen(sk, S)'
#     timer = timeit.Timer(sgen, setup=setup)
#     print('SGen time (ms):')
#     timings = [time/iters for time in timer.repeat(repetitions, iters)]
#     print('\tmin', 1000*min(timings), '\tavg', 1000*(1.0/repetitions)*sum(timings))
#
#     rgen = 'ME.rkgen(sk, R)'
#     timer = timeit.Timer(rgen, setup=setup)
#     print('RGen time (ms):')
#     timings = [time/iters for time in timer.repeat(repetitions, iters)]
#     print('\tmin', 1000*min(timings), '\tavg', 1000*(1.0/repetitions)*sum(timings))
#
#     drgen = '(dkr_, fk) = ME.drgen(sk, R)'
#     timer = timeit.Timer(drgen, setup=setup)
#     print('DRGen time (ms):')
#     timings = [time/iters for time in timer.repeat(repetitions, iters)]
#     print('\tmin', 1000*min(timings), '\tavg', 1000*(1.0/repetitions)*sum(timings))
#
#
#     setup = setup + "\n" + encryption
#
#     decryption = 'ME.test_decrypt(dkr, R, S, C)'
#     timer = timeit.Timer(decryption, setup=setup)
#     print('Decryption time (ms):')
#     timings = [time/iters for time in timer.repeat(repetitions, iters)]
#     print('\tmin', 1000*min(timings), '\tavg', 1000*(1.0/repetitions)*sum(timings))
#
#     setup = setup + "\n" + Dencryption
#
#     sfake = 'ME.test_sfake(pk, eks, R, R_, l_m, l_m_, rr)'
#     timer = timeit.Timer(sfake, setup=setup)
#     print('SFake time (ms):')
#     timings = [time/iters for time in timer.repeat(repetitions, iters)]
#     print('\tmin', 1000*min(timings), '\tavg', 1000*(1.0/repetitions)*sum(timings))
#
#     rfake = 'ME.test_rfake(R_, dkr_, fk, C)'
#     timer = timeit.Timer(rfake, setup=setup)
#     print('RFake time (ms):')
#     timings = [time/iters for time in timer.repeat(repetitions, iters)]
#     print('\tmin', 1000*min(timings), '\tavg', 1000*(1.0/repetitions)*sum(timings))
