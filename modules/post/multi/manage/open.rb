##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Open a file or URL on the target computer',
        'Description' => %q{
          This module will open any file or URL specified with the URI format on the
          target computer via the embedded commands such as 'open' or 'xdg-open'.
        },
        'License' => MSF_LICENSE,
        'Author' => [ 'Eliott Teissonniere'],
        'Platform' => [ 'osx', 'linux', 'win' ],
        'SessionTypes' => [ 'shell', 'meterpreter' ],
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [SCREEN_EFFECTS],
          'Reliability' => []
        }
      )
    )

    register_options(
      [
        OptString.new('URI', [true, 'URI path to open'])
      ]
    )
  end

  #
  # Open a file on OSX using 'open'
  #
  def osx_open(uri)
    cmd_exec("open #{uri}")
    return true
  rescue EOFError
    return false
  end

  #
  # Open a file on Linux using 'xdg-open'
  #
  def linux_open(uri)
    cmd_exec("xdg-open #{uri}")
    return true
  rescue EOFError
    return false
  end

  #
  # Open a file on Windows using 'start'
  #
  def win_open(uri)
    cmd_exec("cmd.exe /c start #{uri}")
    return true
  rescue EOFError
    return false
  end

  def open_uri(uri)
    case session.platform
    when 'osx'
      return osx_open(uri)
    when 'linux'
      return linux_open(uri)
    when 'windows'
      return win_open(uri)
    end
  end

  def run
    uri = datastore['URI']

    print_status("Opening #{uri}")
    if open_uri(uri)
      print_good('Success')
    else
      print_error('Command failed')
    end
  end
end
