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
        'Name'          => 'Enum Domain Users via Powershell',
        'Description'   => %Q{ This module will enumerate the domain users via powershell },
        'License'       => MSF_LICENSE,
        'Author'        => [ 'Ben Turner <benpturner[at]yahoo.com>','Dave Hardy <davehardy20[at]gmail.com>'],
        'Platform'      => [ 'win' ],
        'SessionTypes'  => [ 'powershell' ]
      ))
  end

  # Run Method called when command run is issued
  def run
    print_good("Running the post module: #{name} on: " + session.shell_command('$env:COMPUTERNAME').gsub!(/(\r\n)/, ''))
    # Find all domain users
    pscommand = '$searcher = new-object System.DirectoryServices.DirectorySearcher ; $searcher.filter = "(&(objectClass=user)(sAMAccountName=*))"; $colResults = $searcher.findall()'
    print(session.shell_command(pscommand))
    pscommand = '"`nDomain Users`n=============";foreach ($objResult in $colResults) {$objItem = $objResult.Properties; $objItem.samaccountname } ; "`n"'
    print(session.shell_command(pscommand))
  end
end
