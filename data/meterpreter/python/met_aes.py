import copy
import struct
import sys


def chunks(lst, n):
    for i in range(0, len(lst), n):
        yield lst[i:i + n]


def _cw(word):
    return (word[0] << 24) | (word[1] << 16) | (word[2] << 8) | word[3]


def _s2b(text):
    return list(ord(c)for c in text)


def _b2s(binary):
    return "".join(chr(b)for b in binary)


if sys.version_info[0] >= 3:
    xrange = range

    def _s2b(text):
        if isinstance(text, bytes):
            return text
        return [ord(c)for c in text]

    def _b2s(binary):
        return bytes(binary)
else:
    def bytes(s, e): return s


def _gmul(a, b):
    r = 0
    while b:
        if b & 1:
            r ^= a
        a <<= 1
        if a > 255:
            a ^= 0x11B
        b >>= 1
    return r


def _mix(n, vec):
    return sum(_gmul(n, v) << (24 - 8 * shift) for shift, v in enumerate(vec))


def _ror32(n):
    return (n & 255) << 24 | n >> 8


def _rcon():
    return [_gmul(1, 1 << n) for n in range(30)]


def _Si(S):
    return [S.index(n) for n in range(len(S))]


def _mixl(S, vec):
    return [_mix(s, vec) for s in S]


def _rorl(T):
    return [_ror32(t) for t in T]


empty = struct.pack('')


class AESCBC(object):
    nrs = {16: 10, 24: 12, 32: 14}
    rcon = _rcon()
    S = [
        99, 124, 119, 123, 242, 107, 111, 197, 48, 1, 103, 43, 254, 215, 171,
        118, 202, 130, 201, 125, 250, 89, 71, 240, 173, 212, 162, 175, 156,
        164, 114, 192, 183, 253, 147, 38, 54, 63, 247, 204, 52, 165, 229, 241,
        113, 216, 49, 21, 4, 199, 35, 195, 24, 150, 5, 154, 7, 18, 128, 226,
        235, 39, 178, 117, 9, 131, 44, 26, 27, 110, 90, 160, 82, 59, 214, 179,
        41, 227, 47, 132, 83, 209, 0, 237, 32, 252, 177, 91, 106, 203, 190, 57,
        74, 76, 88, 207, 208, 239, 170, 251, 67, 77, 51, 133, 69, 249, 2, 127,
        80, 60, 159, 168, 81, 163, 64, 143, 146, 157, 56, 245, 188, 182, 218,
        33, 16, 255, 243, 210, 205, 12, 19, 236, 95, 151, 68, 23, 196, 167,
        126, 61, 100, 93, 25, 115, 96, 129, 79, 220, 34, 42, 144, 136, 70, 238,
        184, 20, 222, 94, 11, 219, 224, 50, 58, 10, 73, 6, 36, 92, 194, 211,
        172, 98, 145, 149, 228, 121, 231, 200, 55, 109, 141, 213, 78, 169, 108,
        86, 244, 234, 101, 122, 174, 8, 186, 120, 37, 46, 28, 166, 180, 198,
        232, 221, 116, 31, 75, 189, 139, 138, 112, 62, 181, 102, 72, 3, 246,
        14, 97, 53, 87, 185, 134, 193, 29, 158, 225, 248, 152, 17, 105, 217,
        142, 148, 155, 30, 135, 233, 206, 85, 40, 223, 140, 161, 137, 13, 191,
        230, 66, 104, 65, 153, 45, 15, 176, 84, 187, 22
    ]
    Si = _Si(S)
    T1 = _mixl(S, (2, 1, 1, 3))
    T2 = _rorl(T1)
    T3 = _rorl(T2)
    T4 = _rorl(T3)
    T5 = _mixl(Si, (14, 9, 13, 11))
    T6 = _rorl(T5)
    T7 = _rorl(T6)
    T8 = _rorl(T7)
    U1 = _mixl(range(256), (14, 9, 13, 11))
    U2 = _rorl(U1)
    U3 = _rorl(U2)
    U4 = _rorl(U3)

    def __init__(self, key):
        if len(key)not in (16, 24, 32):
            raise ValueError('Invalid key size')
        rds = self.nrs[len(key)]
        self._Ke = [[0] * 4 for i in xrange(rds + 1)]
        self._Kd = [[0] * 4 for i in xrange(rds + 1)]
        rnd_kc = (rds + 1) * 4
        KC = len(key) // 4
        tk = [struct.unpack('>i', key[i:i + 4])[0]
              for i in xrange(0, len(key), 4)]
        rconpointer = 0
        t = KC
        for i in xrange(0, KC):
            self._Ke[i // 4][i % 4] = tk[i]
            self._Kd[rds - (i // 4)][i % 4] = tk[i]
        while t < rnd_kc:
            tt = tk[KC - 1]
            tk[0] ^= ((self.S[(tt >> 16) & 255] << 24) ^ (self.S[(tt >> 8) & 255] << 16) ^ (
                self.S[tt & 255] << 8) ^ self.S[(tt >> 24) & 255] ^ (self.rcon[rconpointer] << 24))
            rconpointer += 1
            if KC != 8:
                for i in xrange(1, KC):
                    tk[i] ^= tk[i - 1]
            else:
                for i in xrange(1, KC // 2):
                    tk[i] ^= tk[i - 1]
                tt = tk[KC // 2 - 1]
                tk[KC // 2] ^= (self.S[tt & 255] ^ (self.S[(tt >> 8) & 255] << 8) ^
                                (self.S[(tt >> 16) & 255] << 16) ^ (self.S[(tt >> 24) & 255] << 24))
                for i in xrange(KC // 2 + 1, KC):
                    tk[i] ^= tk[i - 1]
            j = 0
            while j < KC and t < rnd_kc:
                self._Ke[t // 4][t % 4] = tk[j]
                self._Kd[rds - (t // 4)][t % 4] = tk[j]
                j += 1
                t += 1
        for r in xrange(1, rds):
            for j in xrange(0, 4):
                tt = self._Kd[r][j]
                self._Kd[r][j] = (self.U1[(tt >> 24) & 255] ^ self.U2[(
                    tt >> 16) & 255] ^ self.U3[(tt >> 8) & 255] ^ self.U4[tt & 255])

    def _encdec(self, data, K, s, S, L1, L2, L3, L4):
        if len(data) != 16:
            raise ValueError('wrong block length')
        rds = len(K) - 1
        (s1, s2, s3) = s
        a = [0, 0, 0, 0]
        t = [(_cw(data[4 * i:4 * i + 4]) ^ K[0][i])for i in xrange(0, 4)]
        for r in xrange(1, rds):
            for i in xrange(0, 4):
                a[i] = L1[(t[i] >> 24) & 255]
                a[i] ^= L2[(t[(i + s1) % 4] >> 16) & 255]
                a[i] ^= L3[(t[(i + s2) % 4] >> 8) & 255]
                a[i] ^= L4[t[(i + s3) % 4] & 255] ^ K[r][i]
            t = copy.copy(a)
        rst = []
        for i in xrange(0, 4):
            tt = K[rds][i]
            rst.append((S[(t[i] >> 24) & 255] ^ (tt >> 24)) & 255)
            rst.append((S[(t[(i + s1) % 4] >> 16) & 255] ^ (tt >> 16)) & 255)
            rst.append((S[(t[(i + s2) % 4] >> 8) & 255] ^ (tt >> 8)) & 255)
            rst.append((S[t[(i + s3) % 4] & 255] ^ tt) & 255)
        return rst

    def enc_in(self, pt):
        return self._encdec(
            pt, self._Ke, [
                1, 2, 3], self.S, self.T1, self.T2, self.T3, self.T4)

    def dec_in(self, ct):
        return self._encdec(
            ct, self._Kd, [
                3, 2, 1], self.Si, self.T5, self.T6, self.T7, self.T8)

    def pad(self, pt):
        c = 16 - (len(pt) % 16)
        return pt + bytes(chr(c) * c, 'utf-8')

    def unpad(self, pt):
        c = pt[-1]
        if not isinstance(c, int):
            c = ord(c)
        return pt[:-c]

    def encrypt(self, iv, pt):
        if len(iv) != 16:
            raise ValueError('initialization vector must be 16 bytes')
        else:
            self._lcb = _s2b(iv)
        pt = self.pad(pt)
        return empty.join([self.enc_b(b)for b in chunks(pt, 16)])

    def enc_b(self, pt):
        if len(pt) != 16:
            raise ValueError('plaintext block must be 16 bytes')
        pt = _s2b(pt)
        pcb = [(p ^ l)for (p, l) in zip(pt, self._lcb)]
        self._lcb = self.enc_in(pcb)
        return _b2s(self._lcb)

    def decrypt(self, iv, ct):
        if len(iv) != 16:
            raise ValueError('initialization vector must be 16 bytes')
        else:
            self._lcb = _s2b(iv)
        if len(ct) % 16 != 0:
            raise ValueError('ciphertext must be a multiple of 16')
        return self.unpad(empty.join([self.dec_b(b)for b in chunks(ct, 16)]))

    def dec_b(self, ct):
        if len(ct) != 16:
            raise ValueError('ciphertext block must be 16 bytes')
        cb = _s2b(ct)
        pt = [(p ^ l)for (p, l) in zip(self.dec_in(cb), self._lcb)]
        self._lcb = cb
        return _b2s(pt)
