import sys
import math
import random
import binascii as ba
import os
from struct import unpack as u
from struct import pack
is2 = sys.version_info[0] < 3


def bt(b):
    if is2:
        return b
    return ord(b)


def b2i(b):
    return int(ba.b2a_hex(b), 16)


def i2b(i):
    h = '%x' % i
    if len(h) % 2 == 1:
        h = '0' + h
    if not is2:
        h = h.encode('utf-8')
    return ba.a2b_hex(h)


def rs(a, o):
    if a[o] == bt(pack('B', 0x81)):
        return (u('B', a[o + 1])[0], 2 + o)
    elif a[o] == bt(pack('B', 0x82)):
        return (u('>H', a[o + 1:o + 3])[0], 3 + o)


def ri(b, o):
    i, o = rs(b, o)
    return (b[o:o + i], o + i)


def b2me(b):
    if b[0] != bt(pack('B', 0x30)):
        return (None, None)
    _, o = rs(b, 1)
    if b[o] != bt(pack('B', 2)):
        return (None, None)
    (m, o) = ri(b, o + 1)
    if b[o] != bt(pack('B', 2)):
        return (None, None)
    e = b[o + 2:]
    return (b2i(m), b2i(e))


def der2me(d):
    if d[0] != bt(pack('B', 0x30)):
        return (None, None)
    _, o = rs(d, 1)
    while o < len(d):
        if d[o] == bt(pack('B', 0x30)):
            o += u('B', d[o + 1:o + 2])[0]
        elif d[o] == bt(pack('B', 0x05)):
            o += 2
        elif d[o] == bt(pack('B', 0x03)):
            _, o = rs(d, o + 1)
            return b2me(d[o + 1:])
        else:
            return (None, None)


def rsa_enc(der, msg):
    m, e = der2me(der)
    h = pack('BB', 0, 2)
    d = pack('B', 0)
    l = 256 - len(h) - len(msg) - len(d)
    p = os.urandom(512).replace(pack('B', 0), pack(''))
    return i2b(pow(b2i(h + p[:l] + d + msg), e, m))
