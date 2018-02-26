##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary

  # Exploit mixins should be called first
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report

  def initialize
    super(
      'Name'        	=> 'Discover External IP via Ifconfig.me',
      'Description'	=> %q{
        This module checks for the public source IP address of the current
        route to the RHOST by querying the public web application at ifconfig.me.
        It should be noted this module will register activity on ifconfig.me,
        which is not affiliated with Metasploit.
      },
      'Author'        => ['RageLtMan'],
      'License'	=> MSF_LICENSE,
      'References'	=>
        [
          [ 'URL', 'http://ifconfig.me/ip' ],
        ]
    )

    register_options(
      [
        Opt::RHOST('ifconfig.me'),
        OptBool.new('REPORT_HOST', [false, 'Add the found IP to the database', false])
      ])
end

  def run
    connect
    res = send_request_cgi({'uri' => '/ip', 'method' => 'GET' })

    if res.nil?
      print_error("Connection timed out")
      return
    end

    our_addr = res.body.strip
    if Rex::Socket.is_ipv4?(our_addr) or Rex::Socket.is_ipv6?(our_addr)
      print_good("Source ip to #{rhost} is #{our_addr}")
      report_host(our_addr) if datastore['REPORT_HOST']
    end
  end
end
