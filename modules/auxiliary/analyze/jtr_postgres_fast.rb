##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Module::Deprecated

  deprecated(Date.new(2019, 10, 30), 'auxiliary/analyze/crack_databases')

  def initialize
    super(
        'Name'           => 'John the Ripper Postgres SQL Password Cracker',
        'Description'    => %Q{
          This module uses John the Ripper to attempt to crack Postgres password
          hashes, gathered by the postgres_hashdump module. It is slower than some of the other
          JtR modules because it has to do some wordlist manipulation to properly handle postgres'
          format.
      },
        'Author'         => ['theLightCosine'],
        'License'        => MSF_LICENSE
    )

  end

  def run
    fail_with(Failure::BadConfig, 'This module has been enhanced and move to: auxiliary/analyze/crack_databases')
  end
end
