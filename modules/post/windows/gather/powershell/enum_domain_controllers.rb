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
        'Name'          => 'Enum Domain Controllors via PowerShell',
        'Description'   => %Q{ This module will enumerate Domain Controllors },
        'License'       => MSF_LICENSE,
        'Author'        => [ 'Ben Turner <benpturner[at]yahoo.com>','Dave Hardy <davehardy20[at]gmail.com>'],
        'Platform'      => [ 'win' ],
        'SessionTypes'  => [ 'powershell' ]
      ))
  end

  # Run Method called when command run is issued
  def run
    print_good("Running the post module: #{name} on: " + session.shell_command('$env:COMPUTERNAME').gsub!(/(\r\n)/, ''))

    pscommand='$root = New-Object DirectoryServices.DirectoryEntry "LDAP://RootDSE"; $root.Properties["dnsHostName"][0].ToString()'
    print(session.shell_command(pscommand))
  end
end
