##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Clear DTCs and Reset MIL',
        'Description' => ' This module clears Diagnostic Trouble Codes and resets the mileage',
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
      OptString.new('ARBID', [false, 'CAN ID to clear DTCs and reset MIL', '0x7DF']),
      OptString.new('CANBUS', [false, 'CAN Bus to perform scan on, defaults to connected bus', nil])
    ])
  end

  def run
    unless client.automotive
      print_error('The hwbridge requires a functional automotive extention')
      return
    end
    print_status('Clearing DTCs and resetting MIL...')
    client.automotive.cansend(datastore['CANBUS'], datastore['ARBID'], '0104555555555555')
  end
end
