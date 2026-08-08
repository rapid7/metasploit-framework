# -*- coding: binary -*-

module Msf
  #
  # Exit routines for Windows ARCH_AArch64 payloads.
  #
  # Mirrors +Msf::Payload::Windows::Exitfunk_x64+: process/thread/none call a
  # kernel32 exit API resolved by ROR-13 hash; seh clears the unhandled
  # exception filter then branches to NULL for a predictable crash.
  #
  module Payload::Windows::Exitfunk_Aarch64 # rubocop:disable Naming/ClassAndModuleCamelCase
    include Msf::Payload::Windows::Aarch64

    #
    # ROR-13 hash of the kernel32 API used for the given EXITFUNC value.
    # For +seh+ this is SetUnhandledExceptionFilter (the call sequence is
    # built by {#asm_exitfunk_aarch64}, not the generic exit-API stub).
    #
    # @param value [String, nil] EXITFUNC datastore value
    # @return [Integer]
    #
    def exitfunk_hash(value)
      case value.to_s.downcase
      when 'thread'
        ror13_hash('ExitThread')
      when 'seh'
        ror13_hash('SetUnhandledExceptionFilter')
      when 'none'
        # Still need a real call so execution does not fall into garbage.
        ror13_hash('ExitProcess')
      when 'process', ''
        0x78b5b983 # TerminateProcess
      else
        0x78b5b983
      end
    end

    #
    # AArch64 assembly for the +exitfunk+ label.
    #
    # Expects kernel32 base at +[x29, #0x00]+ and +&find_function+ at
    # +[x29, #0x08]+ (same slot table as the Windows AArch64 payloads).
    #
    # @option opts [String] :exitfunk One of process, thread, none, seh
    # @return [String] assembly including the +exitfunk:+ label
    #
    def asm_exitfunk_aarch64(opts = {})
      exitfunk = opts[:exitfunk].to_s.downcase
      hash = exitfunk_hash(exitfunk)
      exit_lo = hash & 0xFFFF
      exit_hi = (hash >> 16) & 0xFFFF

      if exitfunk == 'seh'
        <<~ASM
          exitfunk:
            ldr     x3, [x29, #0x00]
            movz    w0, ##{format('0x%04x', exit_lo)}
            movk    w0, ##{format('0x%04x', exit_hi)}, lsl #16
            ldr     x9, [x29, #0x08]
            blr     x9
            mov     x10, x0
            mov     x0, xzr
            blr     x10
            br      xzr
        ASM
      else
        <<~ASM
          exitfunk:
            ldr     x3, [x29, #0x00]
            movz    w0, ##{format('0x%04x', exit_lo)}
            movk    w0, ##{format('0x%04x', exit_hi)}, lsl #16
            ldr     x9, [x29, #0x08]
            blr     x9
            mov     x10, x0
            movn    x0, #0
            mov     w1, wzr
            blr     x10
            brk     #0
        ASM
      end
    end
  end
end
