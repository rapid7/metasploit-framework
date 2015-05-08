##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'msf/core/auxiliary/report'


class Metasploit3 < Msf::Post

  include Msf::Auxiliary::Report

  def initialize(info={})
    super( update_info( info,
        'Name'          => 'Enum Services via PowerShell',
        'Description'   => %Q{ This module will enumerate the ALL services running or stopped },
        'License'       => MSF_LICENSE,
        'Author'        => [ 'Ben Turner <@benpturner>','Dave Hardy <@davehardy20>'],
        'Platform'      => [ 'win' ],
        'SessionTypes'  => [ 'powershell' ]
      ))
  end

  # Run Method called when command run is issued
  def run
    #enumerate the powershell version
    print_good("Running the post module: #{name} on" + session.shell_command('$env:COMPUTERNAME'))
    
    # Get all the services
    pscommand = 'get-service | sort-object status -descending'
    print(session.shell_command(pscommand))
  end
end