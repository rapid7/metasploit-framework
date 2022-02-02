##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(update_info(info,
      'Name' => 'Amazon Fire TV YouTube Remote Control',
      'Description' => %q{
        This module acts as a simple remote control for the Amazon Fire TV's
        YouTube app.

        Tested on the Amazon Fire TV Stick.
      },
      'Author' => ['wvu'],
      'References' => [
        ['URL', 'http://www.amazon.com/dp/B00CX5P8FC?_encoding=UTF8&showFS=1'],
        ['URL', 'http://www.amazon.com/dp/B00GDQ0RMG/ref=fs_ftvs']
      ],
      'License' => MSF_LICENSE,
      'Actions' => [
        ['Play', 'Description' => 'Play video'],
        ['Stop', 'Description' => 'Stop video']
      ],
      'DefaultAction' => 'Play'
    ))

    register_options([
      Opt::RPORT(8008),
      OptString.new('VID', [true, 'Video ID', 'kxopViU98Xo'])
    ])
  end

  def run
    case action.name
    when 'Play'
      stop
      sleep(1)
      res = play
    when 'Stop'
      res = stop
    end

    return unless res

    case res.code
    when 201
      print_good("Playing https://www.youtube.com/watch?v=#{datastore['VID']}")
    when 200
      print_status('Stopping video')
    when 404
      print_error("Couldn't #{action.name.downcase} video")
    end
  end

  def play
    begin
      send_request_cgi(
        'method' => 'POST',
        'uri' => '/apps/YouTube',
        'ctype' => 'text/plain',
        'vars_post' => {
          'v' => datastore['VID']
        }
      )
    rescue Rex::ConnectionRefused, Rex::ConnectionTimeout,
           Rex::HostUnreachable => e
      fail_with(Failure::Unreachable, e)
    end
  end

  def stop
    begin
      send_request_raw(
        'method' => 'DELETE',
        'uri' => '/apps/YouTube/run'
      )
    rescue Rex::ConnectionRefused, Rex::ConnectionTimeout,
           Rex::HostUnreachable => e
      fail_with(Failure::Unreachable, e)
    end
  end
end
