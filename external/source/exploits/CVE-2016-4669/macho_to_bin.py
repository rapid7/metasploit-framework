import sys
import base64

fd = open(sys.argv[1], 'rb')
macho = fd.read()
fd.close()

magic_start = "\x4F\xF0\x00\x00"*4
magic_end = "\x4F\xF0\x01\x00"*4

start = macho.find(magic_start) + len(magic_start) + 2
end   = macho.find(magic_end)
end   = (end & 0xfff0) + 0x10

print("real len: 0x%x" % (end - start))

blob = macho[start:start+0x400]
print("code start: 0x%x" % start)
print("code end: 0x%x" % end)

fd = open(sys.argv[1] + ".b64", "wb+")
fd.write(base64.b64encode(blob))
fd.close()

fd = open(sys.argv[1] + ".bin", "wb+")
fd.write(blob)
fd.close()
