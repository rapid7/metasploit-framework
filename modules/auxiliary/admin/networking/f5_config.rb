##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::F5

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'F5 Configuration Importer',
        'Description' => %q{
          This module imports an F5 device configuration.
        },
        'License' => MSF_LICENSE,
        'Author' => ['h00die']
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
      fail_with Failure::BadConfig, "F5 config file #{datastore['CONFIG']} does not exist!"
    end
    f5_config = ::File.open(datastore['CONFIG'], 'rb')
    print_status('Importing config')
    f5_config_eater(datastore['RHOSTS'], datastore['RPORT'], f5_config.read)
    print_good('Config import successful')
  end
end
