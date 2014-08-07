##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit4 < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(update_info(info,
      'Name'        => 'Apple TV Image Remote Control',
      'Description' => %q(
        This module acts as a simple way to display an image on an Apple TV.
      ),
      'Author'      => ['0a29406d9794e4f9b30b3c5d6702c708'],
      'License'     => MSF_LICENSE
    ))

    register_options([
      Opt::RPORT(7000),
      OptInt.new('TIME', [true, 'Time in seconds to show the image', 10]),
      OptPath.new('FILE', [true, 'Image to show'])
    ], self.class)
  end

  def run
    body = File.open(datastore['FILE'], 'rb') { |f| f.read(f.stat.size) }

    begin
      opts = { 'method' => 'PUT',
               'uri' => '/photo',
               'agent' => 'MediaControl/1.0',
               'data' => body
      }
      nclient = Rex::Proto::Http::Client.new(datastore['RHOST'], datastore['RPORT'],

                                             'Msf'        => framework,
                                             'MsfExploit' => self

      )
      req = nclient.request_raw(opts)
      res = nclient.send_recv(req)
      if res
        if res.code == 200
          print_good("HTTP #{res.code} - Displaying image")
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
