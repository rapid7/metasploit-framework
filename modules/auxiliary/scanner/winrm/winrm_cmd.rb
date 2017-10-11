##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'rex/proto/ntlm/message'



class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::WinRM
  include Msf::Auxiliary::Report


  include Msf::Auxiliary::Scanner

  def initialize
    super(
      'Name'           => 'WinRM Command Runner',
      'Description'    => %q{
        This module runs arbitrary Windows commands using the WinRM Service
        },
      'Author'         => [ 'thelightcosine' ],
      'License'        => MSF_LICENSE
    )

    register_options(
      [
        OptString.new('CMD', [ true, "The windows command to run", "ipconfig /all" ]),
        OptString.new('USERNAME', [ true, "The username to authenticate as"]),
        OptString.new('PASSWORD', [ true, "The password to authenticate with"]),
        OptBool.new('SAVE_OUTPUT', [true, "Store output as loot", false])
      ])
  end


  def run_host(ip)
    streams = winrm_run_cmd(datastore['CMD'])
    return unless streams.class == Hash
    print_error streams['stderr'] unless streams['stderr'] == ''
    print_good streams['stdout']
    if datastore['SAVE_OUTPUT']
      path = store_loot("winrm.cmd_results", "text/plain", ip, streams['stdout'], "winrm_cmd_results.txt", "WinRM CMD Results")
      print_good "Results saved to #{path}"
    end
  end



end
