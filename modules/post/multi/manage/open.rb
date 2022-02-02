##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  def initialize(info={})
    super( update_info( info,
      'Name'          => 'Open a file or URL on the target computer',
      'Description'   => %q{
        This module will open any file or URL specified with the URI format on the
        target computer via the embedded commands such as 'open' or 'xdg-open'.
      },
      'License'       => MSF_LICENSE,
      'Author'        => [ 'Eliott Teissonniere'],
      'Platform'      => [ 'osx', 'linux', 'win' ],
      'SessionTypes'  => [ 'shell', 'meterpreter' ]
    ))

    register_options(
      [
        OptString.new('URI', [true, 'URI path to open'])
      ])
  end

  #
  # The OSX version simply uses 'open'
  #
  def osx_open(uri)
    begin
      cmd_exec("open #{uri}")
    rescue EOFError
      return false
    end

    true
  end

  #
  # The Linux version relies on 'xdg-open'
  #
  def linux_open(uri)
    begin
      cmd_exec("xdg-open #{uri}")
    rescue EOFError
      return false
    end

    true
  end

  def win_open(uri)
    begin
      cmd_exec("cmd.exe /c start #{uri}")
    rescue EOFError
      return false
    end

    true
  end

  def open(uri)
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
    if open(uri)
      print_good('Success')
    else
      print_error('Command failed')
    end
  end
end
