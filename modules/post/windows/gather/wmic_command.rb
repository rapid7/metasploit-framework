##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'rex'
load '/root/git/metasploit-framework/lib/msf/core/post/windows/extapi.rb'
load '/root/git/metasploit-framework/lib/msf/core/post/windows/wmic.rb'

class Metasploit3 < Msf::Post

  include Msf::Post::Windows::WMIC

  def initialize(info={})
    super( update_info( info,
      'Name'          => 'Windows Gather Run Specified WMIC Command',
      'Description'   => %q{ This module will execute a given WMIC command options or read
        WMIC commands options from a resource file and execute the commands in the
        specified Meterpreter session.},
      'License'       => MSF_LICENSE,
      'Author'        => [ 'Carlos Perez <carlos_perez[at]darkoperator.com>'],
      'Platform'      => [ 'win' ],
      'SessionTypes'  => [ 'meterpreter' ]
    ))

    register_options(
      [
        OptPath.new('RESOURCE', [false, 'Full path to resource file to read commands from.']),
        OptString.new('COMMAND', [false, 'WMIC command options.']),
      ], self.class)
  end

  # Run Method for when run command is issued
  def run
    tmpout = ""
    print_status("Running module against #{sysinfo['Computer']}")
    if datastore['RESOURCE']

      if ::File.exists?(datastore['RESOURCE'])

        ::File.open(datastore['RESOURCE']).each_line do |cmd|

          next if cmd.strip.length < 1
          next if cmd[0,1] == "#"
          print_status "Running command #{cmd.chomp}"

          wmic_command(cmd.chomp)

        end
      else
        raise "Resource File does not exists!"
      end

    elsif datastore['COMMAND']

      cmd = datastore['COMMAND']
      result = wmic_command(cmd)

    end
  end

end
