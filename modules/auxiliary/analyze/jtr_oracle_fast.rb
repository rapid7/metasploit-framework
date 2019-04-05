##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Module::Deprecated

  deprecated(Date.new(2019, 10, 30), 'auxiliary/analyze/crack_databases')

  def initialize
    super(
      'Name'           => 'John the Ripper Oracle Password Cracker (Fast Mode)',
      'Description'    => %Q{
          This module uses John the Ripper to identify weak passwords that have been
        acquired from the oracle_hashdump module. Passwords that have been successfully
        cracked are then saved as proper credentials.
      },
      'Author'         =>
        [
          'theLightCosine',
          'hdm'
        ] ,
      'License'        => MSF_LICENSE  # JtR itself is GPLv2, but this wrapper is MSF (BSD)
    )
  end

  def run
    fail_with(Failure::BadConfig, 'This module has been enhanced and move to: auxiliary/analyze/crack_databases')
  end
end
