#!/usr/bin/ruby

#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory

#
# this exemple illustrates the use of the PTrace class to hijack a syscall in a running process
# the next syscall made is patched to run the syscall with the arguments of our choice, then
# run the original intended syscall
# Works on linux/x86
#


require 'metasm'

class SyscallHooker < Metasm::PTrace
  CTX = ['EBX', 'ECX', 'EDX', 'ESI', 'EDI', 'EAX', 'ESP', 'EBP', 'EIP', 'ORIG_EAX']

  def inject(sysnr, *args)
    sysnr = syscallnr[sysnr] || sysnr

    syscall
    puts '[*] waiting syscall'
    Process.waitpid(@pid)

    savedctx = CTX.inject({}) { |ctx, reg| ctx.update reg => peekusr(REGS_I386[reg]) }

    eip = (savedctx['EIP'] - 2) & 0xffffffff
    fu = readmem(eip, 2)
    if fu == "\xcd\x80"
      mode = :int80
    elsif fu == "\xeb\xf3" and readmem(eip-14, 7).unpack('H*').first == "51525589e50f34"	# aoenthuasn
      mode = :sysenter
    elsif fu == "\x0f\x05"
      mode = :syscall
    else
      puts 'unhandled syscall convention, aborting, code = ' + readmem(eip-4, 8).unpack('H*').first
      cont
      return self
    end

    if args.length > 5
      puts 'too may arguments, unsupported, aborting'
    else
      puts "[*] hooking #{syscallnr.index(savedctx['ORIG_EAX'])}"

      # stack pointer to store buffers to
      esp_ptr = savedctx['ESP']
      write_string = lambda { |s|
        esp_ptr -= s.length
        esp_ptr &= 0xffff_fff0
        writemem(esp_ptr, s)
        [esp_ptr].pack('L').unpack('l').first
      }
      set_arg = lambda { |a|
        case a
        when String; write_string[a + 0.chr]
        when Array; write_string[a.map { |aa| set_arg[aa] }.pack('L*')]
        else a
        end
      }
      args.zip(CTX).map { |arg, reg|
        # set syscall args, put buffers on the stack as needed
        pokeusr(REGS_I386[reg], set_arg[arg])
      }
      # patch syscall number
      pokeusr(REGS_I386['ORIG_EAX'], sysnr)


      # run hooked syscall
      syscall
      Process.waitpid(@pid)
      retval = peekusr(REGS_I386['EAX'])
      puts "[*] retval: #{'%X' % retval}#{" (Errno::#{ERRNO.index(-retval)})" if retval < 0}"

      if syscallnr.index(sysnr) == 'execve' and retval >= 0
        cont
        return self
      end

      # restore eax & eip to run the orig syscall
      savedctx['EIP'] -= 2
      savedctx['EAX'] = savedctx['ORIG_EAX']
      savedctx.each { |reg, val| pokeusr(REGS_I386[reg], val) }
    end

    self
  end
end

if $0 == __FILE__
  SyscallHooker.new(ARGV.shift.to_i).inject('write', 2, "testic\n", 7).detach
end
