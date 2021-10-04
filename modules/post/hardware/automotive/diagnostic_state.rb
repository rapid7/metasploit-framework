##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Diagnostic State',
        'Description' => ' This module will keep the vehicle in a diagnostic state on rounds by sending tester present packet',
        'License' => MSF_LICENSE,
        'Author' => ['Jay Turla'],
        'Platform' => ['hardware'],
        'SessionTypes' => ['hwbridge'],
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [PHYSICAL_EFFECTS],
          'Reliability' => []
        }
      )
    )
    register_options([
      OptString.new('ARBID', [false, 'CAN ID to perform Diagnostic State', '0x7DF']),
      OptString.new('CANBUS', [false, 'CAN Bus to perform scan on, defaults to connected bus', nil]),
      OptInt.new('ROUNDS', [true, 'Number of executed rounds', 500])
    ])
  end

  def run
    unless client.automotive
      print_error('The hwbridge requires a functional automotive extention')
      return
    end
    print_status('Putting the vehicle in a diagnostic state...')
    print_status('In order to keep the vehicle in this state, you need to continuously send a packet to let the vehicle know that a diagnostic technician is present.')
    datastore['ROUNDS'].times do
      client.automotive.cansend(datastore['CANBUS'], datastore['ARBID'], '013E')
    end
  end

end
