##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Brocade
  include Msf::Exploit::Deprecated
  moved_from 'auxiliary/admin/brocade/brocade_config'

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Brocade Configuration Importer',
        'Description' => %q{
          This module imports a Brocade device configuration.
        },
        'License' => MSF_LICENSE,
        'Author' => ['h00die'],
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [],
          'Reliability' => []
        }
      )
    )

    register_options(
      [
        OptPath.new('CONFIG', [true, 'Path to configuration to import']),
        Opt::RHOST(),
        Opt::RPORT(22)
      ]
    )
  end

  def run
    unless ::File.exist?(datastore['CONFIG'])
      fail_with Failure::BadConfig, "Brocade config file #{datastore['CONFIG']} does not exist!"
    end
    brocade_config = ::File.open(datastore['CONFIG'], 'rb')
    print_status('Importing config')
    brocade_config_eater(datastore['RHOSTS'], datastore['RPORT'], brocade_config.read)
    print_good('Config import successful')
  end
end
