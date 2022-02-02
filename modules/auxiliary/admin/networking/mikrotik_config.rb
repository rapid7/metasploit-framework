##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Mikrotik

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Mikrotik Configuration Importer',
        'Description' => %q{
          This module imports a Mikrotik device configuration.
        },
        'License' => MSF_LICENSE,
        'Author' => ['h00die'],
        'Actions' => [
          ['ROUTEROS', { 'Description' => 'Import RouterOS Config File' }],
          ['SWOS', { 'Description' => 'Import SwOS Config File' }],
        ],
        'DefaultAction' => 'ROUTEROS'
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
      fail_with(Failure::BadConfig, "Mikrotik config file #{datastore['CONFIG']} does not exist!")
    end
    mikrotik_config = ::File.open(datastore['CONFIG'], 'rb')
    print_status('Importing config')
    if action.name == 'ROUTEROS'
      print_bad('SWB files are typically SWOS, check action') if datastore['CONFIG'].ends_with?('.swb')
      mikrotik_routeros_config_eater(datastore['RHOSTS'], datastore['RPORT'], mikrotik_config.read)
    elsif action.name == 'SWOS'
      mikrotik_swos_config_eater(datastore['RHOSTS'], datastore['RPORT'], mikrotik_config.read)
    end
    print_good('Config import successful')
  end
end
