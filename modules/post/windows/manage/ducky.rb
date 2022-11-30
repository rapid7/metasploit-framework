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
          This module can be used to execute supplied *lightweight* Ducky Scripts - only supports: GUI, STRING, and STRINGLN.
          It also supports sending individual keyevents based on Metasploit's current standards.

          Setting VERBOSE to true will output each line of your file as it is parsed.
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
          'SideEffects' => [CONFIG_CHANGES, ARTIFACTS_ON_DISK, SCREEN_EFFECTS]
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
    # https://learn.microsoft.com/en-us/dotnet/api/system.windows.forms.keys?view=windowsdesktop-7.0
    # Keycode => Key Format
    key_codes = { '8' => 'BACKSPACE', '9' => 'TAB', '10' => 'SHIFT', '11' => 'CONTROL', '13' => 'RETURN',
                  '18' => 'MENU', '20' => 'CAPSLOCK', '32' => 'SPACE', '37' => 'LEFT', '38' => 'UP',
                  '27' => 'ESCAPE', '39' => 'RIGHT', '40' => 'DOWN', '33' => 'PAGEUP', '34' => 'PAGEDOWN',
                  '35' => 'END', '36' => 'HOME', '42' => 'PRINTSCREEN', '46' => 'DELETE', '47' => 'HELP',
                  '65' => 'A', '66' => 'B', '67' => 'C', '68' => 'D', '69' => 'E',
                  '70' => 'F', '71' => 'G', '72' => 'H', '73' => 'I', '74' => 'J',
                  '75' => 'K', '76' => 'L', '77' => 'M', '78' => 'N', '79' => 'O',
                  '80' => 'P', '81' => 'Q', '82' => 'R', '83' => 'S', '84' => 'T',
                  '85' => 'U', '86' => 'V', '87' => 'W', '88' => 'X', '89' => 'Y',
                  '90' => 'Z', '91' => 'WINLEFT', '92' => 'WINRIGHT', '93' => 'WINAPP', '96' => 'NUM0',
                  '97' => 'NUM1', '98' => 'NUM2', '99' => 'NUM3', '100' => 'NUM4', '101' => 'NUM5',
                  '102' => 'NUM6', '103' => 'NUM7', '104' => 'NUM8', '105' => 'NUM9', '106' => 'MULTIPLY',
                  '107' => 'ADD', '109' => 'SUBTRACT', '110' => 'DECIMAL', '111' => 'DIVIDE', '112' => 'F1',
                  '113' => 'F2', '114' => 'F3', '115' => 'F4', '116' => 'F5', '117' => 'F6',
                  '118' => 'F7', '119' => 'F8', '120' => 'F9', '121' => 'F10', '122' => 'F11',
                  '123' => 'F12','188' => 'COMMA','190' => 'PERIOD','191' => 'SLASH','48' => '0',
                  '49' => '1','50' => '2','51' => '3','52' => '4','53' => '5',
                  '54' => '6', '55' => '7', '56' => '8', '57' => '9'
                }
    # Define keypress actions
    actions = { '0' => 'press', '1' => 'down', '2' => 'up' }
    # Parse DuckyScript comments
    if line.starts_with?('REM ')
      return
    end
    # Cursor movement 
    # Althought this is a bit hacky
    cursor_line = line.strip
    if ( cursor_line.eql?('UP') || cursor_line.eql?('DOWN') || cursor_line.eql?('LEFT') || cursor_line.eql?('RIGHT') || cursor_line.eql?('BACKSPACE') ||
      cursor_line.eql?('TAB') || cursor_line.eql?('PAGEUP') || cursor_line.eql?('PAGEDOWN') || cursor_line.eql?('HOME') ||
      cursor_line.eql?('END') || cursor_line.eql?('SPACE') )
      session.ui.keyevent_send(key_codes.key(cursor_line).to_i, actions.key('press').to_i)
    end
    if line.include?('STRING') || line.include?('STRINGLN') || line.include?('GUI')
      line_array = line.split(' ', 2)
      # Write a string and press ENTER
      if line_array[0] == 'STRINGLN'
        session.ui.keyboard_send(line_array[1])
        session.ui.keyevent_send(key_codes.key('RETURN').to_i, actions.key('press').to_i)
      end
      # Write a string
      if line_array[0] == 'STRING'
        session.ui.keyboard_send(line_array[1])
      end
      # Press Windows + R to launch run dialog
      if line_array[0] == 'GUI'
        session.ui.keyevent_send(key_codes.key('WINLEFT').to_i, actions.key('down').to_i)
        session.ui.keyevent_send(key_codes.key('R').to_i, actions.key('press').to_i)
        session.ui.keyevent_send(key_codes.key('WINLEFT').to_i, actions.key('up').to_i)
      end
    end
    if line.include?('KEYEVENT')
      line_array = line.split(' ')
      # Parse raw keyevents; example format, KEYEVENT 82 press
      if line_array[0] == 'KEYEVENT'
        session.ui.keyevent_send(line_array[1].to_i, actions.key(line_array[2]).to_i)
      end
    end
    # Parse F Keys
    if line.starts_with?('F')
      session.ui.keyevent_send(key_codes.key(line).to_i, actions.key('press').to_i)
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
      # Parse out blank lines
      line.split(/\r?\n/)
      next if line.blank?
      if datastore['VERBOSE']
        print_good("Line: #{line}")
      end
      sleep(datastore['SLEEP'])
      ducky_parse(line)
    end
  end
end
