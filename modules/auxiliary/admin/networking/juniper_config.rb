##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Juniper
  include Msf::Exploit::Deprecated
  moved_from 'auxiliary/admin/juniper/juniper_config'

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Juniper Configuration Importer',
        'Description' => %q{
          This module imports a Juniper ScreenOS or JunOS device configuration.
        },
        'License' => MSF_LICENSE,
        'Author' => ['h00die'],
        'Actions' => [
          ['JUNOS', { 'Description' => 'Import JunOS Config File' }],
          ['SCREENOS', { 'Description' => 'Import ScreenOS Config File' }],
        ],
        'DefaultAction' => 'JUNOS',
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
      fail_with Failure::BadConfig, "Juniper config file #{datastore['CONFIG']} does not exist!"
    end
    juniper_config = ::File.open(datastore['CONFIG'], 'rb')
    print_status('Importing config')
    if action.name == 'JUNOS'
      juniper_junos_config_eater(datastore['RHOSTS'], datastore['RPORT'], juniper_config.read)
    elsif action.name == 'SCREENOS'
      juniper_screenos_config_eater(datastore['RHOSTS'], datastore['RPORT'], juniper_config.read)
    end
    print_good('Config import successful')
  end
end
