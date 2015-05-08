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
        'Name'          => 'Enum Service Permissions via PowerShell',
        'Description'   => %Q{ This module will enumerate the ALL services running or stopped },
        'License'       => MSF_LICENSE,
        'Author'        => [ 'Ben Turner <benpturner[at]yahoo.com>','Dave Hardy <davehardy20[at]gmail.com>'],
        'Platform'      => [ 'win' ],
        'SessionTypes'  => [ 'powershell' ]
      ))
  end

  # Run Method called when command run is issued
  def run
    print_good("Running the post module: #{name} on: " + session.shell_command('$env:COMPUTERNAME').gsub!(/(\r\n)/, ''))
    # Get all the services that are not in  "C:\Windows\System32\"
    pscommand = '$services = Get-WmiObject win32_service | ?{$_} | where {($_.pathname -ne $null) -and ($_.pathname -notmatch ".*system32.*")} ; $servicepaths = New-Object System.Collections.ArrayList'
    session.shell_command(pscommand)
    pscommand = 'foreach ($service in $services) { if ($service.PathName -Match "^(.+?)\.exe") {$servicepaths.Add($Matches[0].Replace(\'"\',\'\')) > $null} }'
    session.shell_command(pscommand)
    pscommand = 'foreach ($service in $servicepaths) { "`n"+$service; get-acl $service | select-object -expandproperty AccessToString }'
    print(session.shell_command(pscommand))
  end
end
