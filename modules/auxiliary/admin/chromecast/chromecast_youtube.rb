##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(update_info(info,
      'Name' => 'Chromecast YouTube Remote Control',
      'Description' => %q{
        This module acts as a simple remote control for Chromecast YouTube.

        Only the deprecated DIAL protocol is supported by this module.
        Casting via the newer CASTV2 protocol is unsupported at this time.
      },
      'Author' => ['wvu'],
      'References' => [
        ['URL', 'http://www.google.com/intl/en/chrome/devices/chromecast/index.html'] # vendor website
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
    vid = datastore['VID']

    case action.name
    when 'Play'
      res = play(vid)
    when 'Stop'
      res = stop
    end

    return unless res

    case res.code
    when 201
      print_good("Playing https://www.youtube.com/watch?v=#{vid}")
    when 200
      print_status('Stopping video')
    when 404
      print_error("#{action.name} failed: DIAL protocol unsupported")
    end
  end

  def play(vid)
    begin
      send_request_cgi(
        'method' => 'POST',
        'uri' => '/apps/YouTube',
        'agent' => Rex::Text.rand_text_english(rand(42) + 1),
        'vars_post' => {
          'v' => vid
        }
      )
    rescue Rex::ConnectionRefused, Rex::ConnectionTimeout,
           Rex::HostUnreachable => e
      fail_with(Failure::Unreachable, e)
    ensure
      disconnect
    end
  end

  def stop
    begin
      send_request_raw(
        'method' => 'DELETE',
        'uri' => '/apps/YouTube',
        'agent' => Rex::Text.rand_text_english(rand(42) + 1)
      )
    rescue Rex::ConnectionRefused, Rex::ConnectionTimeout,
           Rex::HostUnreachable => e
      fail_with(Failure::Unreachable, e)
    ensure
      disconnect
    end
  end
end
