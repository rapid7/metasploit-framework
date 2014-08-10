##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit4 < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(update_info(info,
      'Name'        => 'Apple TV Video Remote Control',
      'Description' => %q(
        This module acts as a simple way to display a video on an Apple TV.
      ),
      'Author'      => ['0a29406d9794e4f9b30b3c5d6702c708'],
      'License'     => MSF_LICENSE
    ))

    register_options([
      Opt::RPORT(7000),
      OptInt.new('TIME', [true, 'Time in seconds to show the video', 60]),
      OptString.new('URL', [true, 'URL of video to show. Must use an IP address'])
    ], self.class)
  end

  def run
    body = 'Content-Location: ' + datastore['URL'] + "\n"
    body += "Start-Position: 0.0\n"
    opts = { 'method' => 'POST',
             'uri' => '/play',
             'agent' => 'MediaControl/1.0',
             'headers' =>
              {
                'Content-Length' => body.length,
                'Content-Type' => 'text/parameters'
              },
             'data' => body
    }
    begin
      nclient = Rex::Proto::Http::Client.new(datastore['RHOST'], datastore['RPORT'],
                                             'Msf'        => framework,
                                             'MsfExploit' => self
      )
      req = nclient.request_raw(opts)
      res = nclient.send_recv(req)
      if res
        if res.code == 200
          print_good("HTTP #{res.code} - Displaying video")
          sleep(datastore['TIME'])
        else
          print_error("HTTP #{res.code} - Request failed")
        end
      else
        print_error('Request failed')
      end
      nclient.close
    rescue Rex::ConnectionRefused, Rex::ConnectionTimeout, Rex::HostUnreachable => e
      fail_with(Failure::Unreachable, e)
    ensure
      cleanup
    end
  end
end
