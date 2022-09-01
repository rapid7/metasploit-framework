##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Arista

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Arista Configuration Importer',
        'Description' => %q{
          This module imports an Arista device configuration.
        },
        'License' => MSF_LICENSE,
        'Author' => [ 'h00die' ]
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
      fail_with Failure::BadConfig, "Arista config file #{datastore['CONFIG']} does not exist!"
    end
    arista_config = ::File.open(datastore['CONFIG'], 'rb')
    print_status('Importing config')
    arista_eos_config_eater(datastore['RHOSTS'], datastore['RPORT'], arista_config.read)
    print_good('Config import successful')
  end
end
