#!/usr/bin/ruby

#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2008 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory

#
# this exemple illustrates the use of the PTrace32 class to hijack a syscall in a running process
# the next syscall made is patched to run the syscall with the arguments of our choice, then
# run the original intended syscall
# Works on linux/x86
#


require 'metasm'

class SyscallHooker < Metasm::PTrace32
	CTX = ['EBX', 'ECX', 'EDX', 'ESI', 'EDI', 'EAX', 'ESP', 'EBP', 'EIP', 'ORIG_EAX']

	def inject(sysnr, *args)
		sysnr = SYSCALLNR[sysnr] || sysnr

		syscall
		puts '[*] waiting syscall'
		Process.waitpid(@pid)

		savedctx = CTX.inject({}) { |ctx, reg| ctx.update reg => peekusr(REGS_I386[reg]) }

		if readmem((savedctx['EIP'] - 2) & 0xffff_ffff, 2) != "\xcd\x80"
			puts 'no int 80h seen, cannot replay orig syscall, aborting'
		elsif args.length > 5
			puts 'too may arguments, unsupported, aborting'
		else
			puts "[*] hooking #{SYSCALLNR.index(savedctx['ORIG_EAX'])}"

			# stack pointer to store buffers to
			esp_ptr = savedctx['ESP']
			args.zip(CTX).map { |arg, reg|
				# set syscall args, put buffers on the stack as needed
				if arg.kind_of? String
					esp_ptr -= arg.length
					esp_ptr &= 0xffff_fff0
					writemem(esp_ptr, arg)
					arg = [esp_ptr].pack('L').unpack('l').first
				end
				pokeusr(REGS_I386[reg], arg)
			}
			# patch syscall number
			pokeusr(REGS_I386['ORIG_EAX'], sysnr)
			# run hooked syscall
			syscall
			Process.waitpid(@pid)
			puts "[*] retval: #{'%X' % peekusr(REGS_I386['EAX'])}"

			# restore eax & eip to run the orig syscall
			savedctx['EIP'] -= 2
			savedctx['EAX'] = savedctx['ORIG_EAX']
			savedctx.each { |reg, val| pokeusr(REGS_I386[reg], val) }
		end
		cont
	end
end

if $0 == __FILE__
	SyscallHooker.new(ARGV.shift.to_i).inject('write', 2, "testic\n", 7)
end
